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
	"net/http"
	"net/http/httptest"
	"testing"

	"mibee-steward/internal/config"
)

// TestSTUNParse pins both mapped-address flavors: the RFC 5389 XOR form and
// the legacy plain form.
func TestSTUNParse(t *testing.T) {
	// XOR-MAPPED-ADDRESS: address bytes pre-XORed with the magic cookie.
	m := make([]byte, 20)
	binary.BigEndian.PutUint16(m[2:4], 12) // attr header (4) + value (8)
	xv := make([]byte, 8)
	xv[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(xv[2:4], 0x4431^0x2112)
	binary.BigEndian.PutUint32(xv[4:8], binary.BigEndian.Uint32([]byte{93, 184, 216, 34})^0x2112A442)
	xbody := append([]byte{0x00, 0x20, 0, 8}, xv...)
	if got := parseSTUNMappedAddress(append(m, xbody...)); got != "93.184.216.34" {
		t.Errorf("xor mapped = %q, want 93.184.216.34", got)
	}
	// Plain MAPPED-ADDRESS (no XOR).
	m = make([]byte, 20)
	binary.BigEndian.PutUint16(m[2:4], 12) // attr header (4) + value (8)
	pv := make([]byte, 8)
	pv[1] = 0x01
	copy(pv[4:8], []byte{198, 51, 100, 3})
	pbody := append([]byte{0x00, 0x01, 0, 8}, pv...)
	if got := parseSTUNMappedAddress(append(m, pbody...)); got != "198.51.100.3" {
		t.Errorf("plain mapped = %q, want 198.51.100.3", got)
	}
}

// TestIsPublicIP pins the scope decisions; CGNAT counts as the egress
// identity on purpose.
func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"93.184.216.34": true,  // example.com: genuinely public
		"203.0.113.7":   false, // TEST-NET-3 is documentation space
		"192.0.2.1":     false, // TEST-NET-1
		"198.51.100.3":  false, // TEST-NET-2
		"100.64.1.2":    true,  // CGNAT
		"10.1.2.3":      false,
		"192.168.1.1":   false,
		"172.16.0.1":    false,
		"127.0.0.1":     false,
		"169.254.1.1":   false,
		"223.5.5.5":     true,
		"not-an-ip":     false,
		"2001:db8::1":   false, // IPv6 not an IPv4 string
	}
	for ip, want := range cases {
		if got := isPublicIP(ip); got != want {
			t.Errorf("isPublicIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

// TestHTTPEcho pins body extraction: plain-IP bodies, the cdn-cgi/trace
// ip= line, status errors, and bodies without any IPv4.
func TestHTTPEcho(t *testing.T) {
	c := newEgressCollector(config.ProbeEgressConfig{}, nil)
	t.Run("plain body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("93.184.216.34\n"))
		}))
		defer srv.Close()
		ip, err := c.httpEcho(context.Background(), srv.URL)
		if err != "" || ip != "93.184.216.34" {
			t.Fatalf("ip=%q err=%q", ip, err)
		}
	})
	t.Run("trace body prefers ip line", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("fl=abc\nip=93.184.216.35\nloc=CN\n"))
		}))
		defer srv.Close()
		ip, _ := c.httpEcho(context.Background(), srv.URL)
		if ip != "93.184.216.35" {
			t.Fatalf("ip=%q", ip)
		}
	})
	t.Run("status error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotImplemented)
		}))
		defer srv.Close()
		if _, err := c.httpEcho(context.Background(), srv.URL); err == "" {
			t.Fatal("want an error for 501")
		}
	})
	t.Run("documentation ip rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("192.0.2.9\n"))
		}))
		defer srv.Close()
		if ip, err := c.httpEcho(context.Background(), srv.URL); ip != "" || err == "" {
			t.Fatalf("ip=%q err=%q, want rejection", ip, err)
		}
	})
}

// TestHostPortForTrace pins the target-string → (host, port) mapping that
// decides the trace method.
func TestHostPortForTrace(t *testing.T) {
	cases := []struct {
		module, target, host string
		port                 int
	}{
		{"http", "https://www.example.com", "www.example.com", 443},
		{"http", "http://www.example.com", "www.example.com", 80},
		{"http", "https://www.example.com:8443/", "www.example.com", 8443},
		{"tls", "www.example.com:443", "www.example.com", 443},
		{"tcp", "1.2.3.4:53", "1.2.3.4", 53},
		{"icmp", "www.example.com", "www.example.com", 0},
		{"dns", "223.5.5.5", "223.5.5.5", 0},
	}
	for _, c := range cases {
		host, port := hostPortForTrace(testTarget(c.module, c.target))
		if host != c.host || port != c.port {
			t.Errorf("hostPortForTrace(%s, %s) = %q:%d, want %q:%d", c.module, c.target, host, port, c.host, c.port)
		}
	}
}
