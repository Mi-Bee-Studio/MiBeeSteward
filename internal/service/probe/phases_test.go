// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPhasesHasData pins the storage gate (#717): only a run that measured
// at least one stage (or resolved an address) produces a probe_phases row.
func TestPhasesHasData(t *testing.T) {
	if (&Phases{}).HasData() {
		t.Error("zero phases must not count as data")
	}
	var nilP *Phases
	if nilP.HasData() {
		t.Error("nil phases must not count as data")
	}
	for _, p := range []Phases{
		{DNSMs: 1},
		{ConnectMs: 1},
		{TLSMs: 1},
		{TTFBMs: 1},
		{ReplyTTL: 64},
		{ResolvedIP: "192.0.2.1"},
	} {
		if !p.HasData() {
			t.Errorf("%+v should count as data", p)
		}
	}
}

// TestHTTPProbe_Phases pins the httptrace breakdown (#717): a successful
// loopback run resolves the connection address, keeps non-negative stages,
// and the measured stages never exceed the whole-run latency. Loopback URLs
// carry an IP literal, so the DNS stage legitimately stays 0 here.
func TestHTTPProbe_Phases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := (&HTTPProber{}).Probe(context.Background(), server.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !result.Success || result.Phases == nil {
		t.Fatalf("success result without phases: %+v", result)
	}
	ph := result.Phases
	if !ph.HasData() {
		t.Fatalf("successful http run must carry phase data: %+v", ph)
	}
	if ph.ResolvedIP != "127.0.0.1" {
		t.Errorf("ResolvedIP = %q, want 127.0.0.1", ph.ResolvedIP)
	}
	for _, st := range []struct {
		name string
		v    float64
	}{
		{"dns_ms", ph.DNSMs},
		{"connect_ms", ph.ConnectMs},
		{"tls_ms", ph.TLSMs},
		{"ttfb_ms", ph.TTFBMs},
	} {
		if st.v < 0 {
			t.Errorf("%s = %v, must be non-negative", st.name, st.v)
		}
	}
	// The traced stages are sub-intervals of the run; allow a tiny slack for
	// clock granularity at sub-millisecond loopback latencies.
	if sum := ph.DNSMs + ph.ConnectMs + ph.TLSMs + ph.TTFBMs; sum > result.Latency.Seconds()*1000+1 {
		t.Errorf("stage sum %.3fms exceeds run latency %.3fms", sum, result.Latency.Seconds()*1000)
	}
}

// TestHTTPProbe_PhasesOnFailure: a refused/dropped dial keeps the stages that
// did complete — the diagnostic payload of #717 lives on failed runs too.
func TestHTTPProbe_PhasesOnFailure(t *testing.T) {
	// A closed port on loopback: the dial starts (connect stage anchored) and
	// fails fast with connection refused.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := server.URL
	server.Close()

	result, err := (&HTTPProber{}).Probe(context.Background(), url, 2*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure against a closed port")
	}
	// The connect anchor fired even though the dial failed; at minimum the
	// resolved address is known. Either way the result must not panic and the
	// phases (when present) stay non-negative.
	if result.Phases != nil {
		if result.Phases.ConnectMs < 0 || result.Phases.DNSMs < 0 {
			t.Errorf("negative stages on failure: %+v", result.Phases)
		}
	}
}

// TestTCPProbe_Phases pins the tcp module's breakdown (#717): connect-ms is
// the whole run and the resolved address comes off the established socket.
func TestTCPProbe_Phases(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	result, err := (&TCPProber{}).Probe(context.Background(), ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !result.Success || result.Phases == nil {
		t.Fatalf("success result without phases: %+v", result)
	}
	if result.Phases.ResolvedIP != "127.0.0.1" {
		t.Errorf("ResolvedIP = %q, want 127.0.0.1", result.Phases.ResolvedIP)
	}
	if result.Phases.ConnectMs < 0 {
		t.Errorf("ConnectMs = %v, must be non-negative", result.Phases.ConnectMs)
	}
}

// TestICMPProbe_Phases pins the icmp module's breakdown (#717): a loopback
// echo reports the reply TTL. Unprivileged ICMP needs the OS ping socket
// (net.ipv4.ping_group_range); environments without it skip.
func TestICMPProbe_Phases(t *testing.T) {
	result, err := (&ICMPProber{}).Probe(context.Background(), "127.0.0.1", 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !result.Success {
		if result.Phases == nil && strings.Contains(result.ErrorMessage, "operation not permitted") {
			t.Skipf("unprivileged ICMP unavailable here: %s", result.ErrorMessage)
		}
		t.Fatalf("icmp probe failed: %s", result.ErrorMessage)
	}
	if result.Phases == nil {
		t.Fatal("successful icmp run must carry phases")
	}
	if result.Phases.ReplyTTL <= 0 {
		t.Errorf("ReplyTTL = %d, want > 0 on loopback", result.Phases.ReplyTTL)
	}
	if result.Phases.ResolvedIP != "127.0.0.1" {
		t.Errorf("ResolvedIP = %q, want 127.0.0.1", result.Phases.ResolvedIP)
	}
}
