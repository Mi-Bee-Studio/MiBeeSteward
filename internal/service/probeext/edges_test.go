// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//go:build linux

package probeext

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mibee-steward/internal/config"
)

// TestTickDisabledEarlyReturn pins the tick short-circuit when tracing has
// no categories (egress off + nothing to trace).
func TestTickDisabledEarlyReturn(t *testing.T) {
	queries, _ := openTestQueries(t)
	store := openTestStore(t)
	cfg := testServiceCfg()
	cfg.Egress.Enabled = false
	cfg.Trace.Categories = nil
	svc := NewService(cfg, store, queries, nil)
	svc.tick(context.Background()) // must neither round nor trace
	if views, _ := store.LatestEgress(context.Background(), time.Hour); len(views) != 0 {
		t.Fatalf("egress ran despite disabled: %+v", views)
	}
}

// TestStartLoopRunsTick pins the scheduler loop driving tick() on a short
// interval and exiting on context cancel.
func TestStartLoopRunsTick(t *testing.T) {
	queries, _ := openTestQueries(t)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)
	ctx, cancel := context.WithCancel(context.Background())
	svc.startLoop(ctx, 40*time.Millisecond)
	time.Sleep(150 * time.Millisecond) // ≥2 ticks
	cancel()
	if _, ok := svc.nextTrace[0]; false && !ok {
		t.Fatal("unreachable")
	}
	// The egress schedule was seeded (tick ran at least once).
	svc.mu.Lock()
	seeded := !svc.nextEgress.IsZero()
	svc.mu.Unlock()
	if !seeded {
		t.Fatal("tick never ran")
	}
}

// TestRoundUnknownKindSource pins the round's unknown-kind guard row.
func TestRoundUnknownKindSource(t *testing.T) {
	httpSrv := startLocalIPServer(t, "93.184.216.120")
	store := openTestStore(t)
	cfg := config.ProbeEgressConfig{
		IntervalSeconds: 300,
		Sources: []config.ProbeEgressSource{
			{Name: "http-ok", Kind: "http", Target: httpSrv},
			{Name: "pigeon", Kind: "carrier-pigeon", Target: "coop"},
		},
	}
	if err := newEgressCollector(cfg, nil).round(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	views, _ := store.LatestEgress(context.Background(), time.Hour)
	for _, s := range views[0].Sources {
		if s.Source == "pigeon" && (s.OK || s.Err != "unknown kind carrier-pigeon") {
			t.Fatalf("pigeon row = %+v", s)
		}
	}
}

// TestTraceDueConcurrency pins the concurrency-bounded fan-out: two due
// external targets both get traced.
func TestTraceDueConcurrency(t *testing.T) {
	srv := startLocalIPServer(t, "")
	queries, conn := openTestQueries(t)
	insertTarget(t, conn, 11, "ext-a", "http", srv, "manual", true, nil)
	insertTarget(t, conn, 12, "ext-b", "http", srv, "manual", true, nil)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)
	now := time.Now()
	svc.traceDueTargets(context.Background(), now)
	svc.mu.Lock()
	for id := range svc.nextTrace {
		svc.nextTrace[id] = now.Add(-time.Minute)
	}
	svc.mu.Unlock()
	svc.traceDueTargets(context.Background(), now.Add(time.Second))
	paths, _ := store.LatestPaths(context.Background(), "")
	if len(paths) != 2 {
		t.Fatalf("paths = %d, want both targets traced", len(paths))
	}
}

// TestHTTPEchoClientFailure pins the transport-error branch via a zero
// client timeout.
func TestHTTPEchoClientFailure(t *testing.T) {
	srv := startLocalIPServer(t, "93.184.216.121")
	c := newEgressCollector(config.ProbeEgressConfig{}, nil)
	c.client = &http.Client{Timeout: time.Nanosecond}
	if _, errMsg := c.httpEcho(context.Background(), srv); errMsg == "" {
		t.Fatal("nano-timeout request must fail")
	}
}

// TestTraceImmediateConnectError pins the connect-error branch (an address
// that fails synchronously rather than with EINPROGRESS).
func TestTraceImmediateConnectError(t *testing.T) {
	tr := NewTracer(2, 200, 1)
	res := tr.TraceHost(context.Background(), "0.0.0.0", 1, "tcp")
	if res.Err != "" {
		t.Fatalf("unexpected err: %s", res.Err)
	}
	// Whatever the kernel answers (reject or silence), the walk must
	// terminate without panicking; a reject from the stack counts as
	// reached, silence as max_ttl.
	if res.EndState != "reached" && res.EndState != "max_ttl" {
		t.Fatalf("end state = %q", res.EndState)
	}
}

// TestTraceHostCancelled pins the resolve-error branch through a cancelled
// context.
func TestTraceHostCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr := NewTracer(2, 100, 1)
	res := tr.TraceHost(ctx, "www.example.invalid", 0, "icmp")
	if res.EndState != "error" || res.Err == "" {
		t.Fatalf("res = %+v, want error end state", res)
	}
}

// TestLookupASNSecondResolver pins the resolver-preference loop continuing
// past a dead first entry.
func TestLookupASNSecondResolver(t *testing.T) {
	alive := fakeDNSTXT(t, map[string]string{
		"7.0.0.10.origin.asn.cymru.com": "64520 | 203.0.113.0/24 | ZZ | test | 2026-01-01",
	})
	c := newEgressCollector(config.ProbeEgressConfig{
		ASNResolvers: []string{"127.0.0.1:1", alive},
	}, nil)
	asn, _ := c.lookupASN(context.Background(), "10.0.0.7")
	if asn != "64520" {
		t.Fatalf("asn = %q, want the second resolver's answer", asn)
	}
}

// TestStUNRetry pins the two-attempt loop: a server that drops the first
// datagram still yields the address on the second.
func TestSTUNRetry(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	seen := 0
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			seen++
			if seen == 1 {
				continue // drop the first
			}
			resp := make([]byte, 32)
			copy(resp, buf[:n])
			resp[0] &= 0xFC
			// XOR-MAPPED-ADDRESS 198.51.100.3-style would be rejected by
			// scope rules, so answer with a public example address.
			putXORMapped(resp, net.IPv4(93, 184, 216, 130))
			_, _ = conn.WriteToUDP(resp, from)
		}
	}()
	ip, errMsg := stunEcho(conn.LocalAddr().String(), 2*time.Second)
	if errMsg != "" {
		t.Fatalf("stun err: %s", errMsg)
	}
	if ip != "93.184.216.130" {
		t.Fatalf("ip = %q", ip)
	}
}

func putXORMapped(resp []byte, ip net.IP) {
	resp[2], resp[3] = 0, 12
	v4 := ip.To4()
	x := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	x ^= 0x2112A442
	resp[20], resp[21] = 0x00, 0x20
	resp[22], resp[23] = 0, 8
	resp[24], resp[25] = 0, 0x01
	resp[26], resp[27] = 0x21, 0x12
	resp[28], resp[29] = byte(x>>24), byte(x>>16)
	resp[30], resp[31] = byte(x>>8), byte(x)
}

func startLocalIPServer(t *testing.T, bodyIP string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if bodyIP != "" {
			_, _ = w.Write([]byte(bodyIP + "\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
