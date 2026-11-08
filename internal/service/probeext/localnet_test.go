// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mibee-steward/internal/config"
)

// The egress collector's network paths (STUN, DNS echo, Cymru ASN) are all
// plain UDP request/response protocols, so local fake servers cover them
// without any external dependency.

// fakeSTUN answers binding requests with an XOR-MAPPED-ADDRESS for ip.
func fakeSTUN(t *testing.T, ip net.IP) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			// Echo the header with a success response + one XOR attribute.
			resp := make([]byte, 20, 32)
			copy(resp, buf[:20])
			resp[0] &= 0xFC // class: success response
			binary.BigEndian.PutUint16(resp[2:4], 12)
			attr := make([]byte, 12)
			binary.BigEndian.PutUint16(attr[0:2], 0x0020)
			binary.BigEndian.PutUint16(attr[2:4], 8)
			attr[2] = 0
			binary.BigEndian.PutUint16(attr[2:4], 8)
			attr[4] = 0
			attr[5] = 0x01
			binary.BigEndian.PutUint16(attr[6:8], 0x2112)
			v4 := ip.To4()
			xored := binary.BigEndian.Uint32(v4) ^ 0x2112A442
			binary.BigEndian.PutUint32(attr[8:12], xored)
			resp = append(resp, attr...)
			_, _ = conn.WriteToUDP(resp, from)
		}
	}()
	return conn.LocalAddr().String()
}

// fakeDNSTXT answers every query with one TXT record carrying the given
// strings (sufficient for the echo + Cymru shapes the collector uses).
func fakeDNSTXT(t *testing.T, answers map[string]string) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil || n < 12 {
				return
			}
			q := buf[:n]
			// Copy the question section verbatim; find its end (zero label).
			i := 12
			for i < n && q[i] != 0 {
				i += 1 + int(q[i])
			}
			i += 5 // root + qtype + qclass
			resp := make([]byte, 0, i+32)
			resp = append(resp, q[:12]...)
			resp[2] |= 0x80 // QR=response
			resp[3] = 0x80  // RD + RA
			resp = append(resp, q[12:i]...)
			// counts: 1 question already in header; add 1 answer
			binary.BigEndian.PutUint16(resp[6:8], 1)
			txt := answers[strings.ToLower(questionName(q))]
			if txt == "" {
				txt = answers["*"]
			}
			// answer: pointer to qname (0xC00C), TXT, IN, ttl 60, rdlen
			resp = append(resp, 0xC0, 0x0C, 0, 16, 0, 1)
			ttl := make([]byte, 4)
			binary.BigEndian.PutUint32(ttl, 60)
			resp = append(resp, ttl...)
			str := txt
			if len(str) > 200 {
				str = str[:200]
			}
			rd := append([]byte{byte(len(str))}, []byte(str)...)
			rdlen := make([]byte, 2)
			binary.BigEndian.PutUint16(rdlen, uint16(len(rd)))
			resp = append(resp, rdlen...)
			resp = append(resp, rd...)
			_, _ = conn.WriteToUDP(resp, from)
		}
	}()
	return conn.LocalAddr().String()
}

// questionName extracts the dotted qname from a raw query.
func questionName(q []byte) string {
	var sb strings.Builder
	i := 12
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		i++
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(q[i : i+l])
		i += l
	}
	return sb.String()
}

// TestSTUNEchoLocal pins the full STUN echo against a fake server: the
// XOR-MAPPED address comes back as the observed IP.
func TestSTUNEchoLocal(t *testing.T) {
	server := fakeSTUN(t, net.IPv4(203, 0, 113, 99)) // value irrelevant to scope checks here
	ip, err := stunEcho(server, 2*time.Second)
	if err != "" {
		t.Fatalf("stunEcho err: %s", err)
	}
	if ip != "203.0.113.99" {
		t.Fatalf("ip = %q, want 203.0.113.99", ip)
	}
	if _, err := stunEcho("127.0.0.1:1", 300*time.Millisecond); err == "" {
		t.Fatal("unreachable server must report an error")
	}
}

// TestDNSEchoLocal pins the authoritative-resolver echo against a fake TXT
// server.
func TestDNSEchoLocal(t *testing.T) {
	server := fakeDNSTXT(t, map[string]string{"*": "93.184.216.100"})
	c := newEgressCollector(config.ProbeEgressConfig{}, nil)
	ip, err := c.dnsEcho(context.Background(), server+"|whoami.example")
	if err != "" {
		t.Fatalf("dnsEcho err: %s", err)
	}
	if ip != "93.184.216.100" {
		t.Fatalf("ip = %q", ip)
	}
	if _, err := c.dnsEcho(context.Background(), "bad-target"); err == "" {
		t.Fatal("malformed dns target must error")
	}
}

// TestLookupASNLocal pins the Cymru parse through a fake resolver: the
// origin TXT "asn | prefix | cc | reg | date" plus the AS-name second query.
func TestLookupASNLocal(t *testing.T) {
	server := fakeDNSTXT(t, map[string]string{
		"7.0.0.10.origin.asn.cymru.com": "64512 | 203.0.113.0/24 | ZZ | test | 2026-01-01",
		"as64512.asn.cymru.com":         "64512 | 203.0.113.0/24 | ZZ | test | 2026-01-01 | Example AS",
	})
	c := newEgressCollector(config.ProbeEgressConfig{ASNResolvers: []string{server}}, nil)
	asn, name := c.lookupASN(context.Background(), "10.0.0.7")
	if asn != "64512" {
		t.Fatalf("asn = %q, want 64512", asn)
	}
	if name != "Example AS" {
		t.Fatalf("as name = %q, want the fifth field", name)
	}
	// Cache: a resolver that now fails must still serve the cached entry.
	c.cfg.ASNResolvers = []string{"127.0.0.1:1"}
	asn2, name2 := c.lookupASN(context.Background(), "10.0.0.7")
	if asn2 != asn || name2 != name {
		t.Fatalf("cache miss: %q/%q", asn2, name2)
	}
	// Unresolvable IP keeps empty fields without panicking.
	asn3, _ := c.lookupASN(context.Background(), "10.0.0.8")
	if asn3 != "" {
		t.Fatalf("asn3 = %q, want empty", asn3)
	}
}

// TestEgressRoundLocal runs one full round with every source pointed at
// local fakes plus a local HTTP echo, then asserts the persisted shape.
func TestEgressRoundLocal(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("93.184.216.101\n"))
	}))
	defer httpSrv.Close()
	stunSrv := fakeSTUN(t, net.IPv4(203, 0, 113, 102))
	dnsSrv := fakeDNSTXT(t, map[string]string{"*": "93.184.216.103"})
	asnSrv := fakeDNSTXT(t, map[string]string{
		"101.216.184.93.origin.asn.cymru.com": "64512 | 203.0.113.0/24 | ZZ | test | 2026-01-01",
		"as64512.asn.cymru.com":               "64512 | 203.0.113.0/24 | ZZ | test | 2026-01-01 | Example AS",
	})
	store := openTestStore(t)
	cfg := config.ProbeEgressConfig{
		IntervalSeconds: 300,
		ASNResolvers:    []string{asnSrv},
		Sources: []config.ProbeEgressSource{
			{Name: "http-local", Kind: "http", Target: httpSrv.URL},
			{Name: "stun-local", Kind: "stun", Target: stunSrv},
			{Name: "dns-local", Kind: "dns", Target: dnsSrv + "|whoami.example"},
			{Name: "http-dead", Kind: "http", Target: "http://127.0.0.1:1"},
		},
	}
	c := newEgressCollector(cfg, nil)
	if err := c.round(context.Background(), store); err != nil {
		t.Fatalf("round: %v", err)
	}
	views, err := store.LatestEgress(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("views = %d", len(views))
	}
	v := views[0]
	if len(v.IPs) != 3 {
		t.Fatalf("ips = %+v, want the three distinct fake IPs", v.IPs)
	}
	byIP := map[string]EgressIPView{}
	for _, ip := range v.IPs {
		byIP[ip.IP] = ip
	}
	if got := byIP["93.184.216.101"]; got.ASN != "64512" {
		t.Errorf("http ip asn = %q, want 64512 (asn enrich ran)", got.ASN)
	}
	// The dead source recorded as a failure row.
	deadOK := false
	for _, s := range v.Sources {
		if s.Source == "http-dead" && !s.OK && s.Err != "" {
			deadOK = true
		}
	}
	if !deadOK {
		t.Errorf("dead source not recorded: %+v", v.Sources)
	}
}

// TestParseProcNetRoute pins the little-endian hex parsing.
func TestParseProcNetRoute(t *testing.T) {
	gw, iface := parseProcNetRoute("Iface\tDestination\tGateway\tFlags\tMask\tMTU\tWin\tIRT\n" +
		"eth0\t00000000\t0102A8C0\t0003\t00000000\t0\t0\t0\n" +
		"eth0\t0002A8C0\t00000000\t0001\tFFFFFF00\t0\t0\t0\n")
	if gw != "192.168.2.1" || iface != "eth0" {
		t.Fatalf("gw/iface = %q/%q, want 192.168.2.1/eth0", gw, iface)
	}
	if gw, _ := parseProcNetRoute("header only"); gw != "" {
		t.Fatalf("no rows must give empty, got %q", gw)
	}
	if gw, _ := parseProcNetRoute("Iface D G F\nlo 00000000 ZZ 0003"); gw != "" {
		t.Fatalf("malformed hex must give empty, got %q", gw)
	}
}
