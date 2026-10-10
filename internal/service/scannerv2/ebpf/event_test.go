// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package ebpf

import (
	"encoding/binary"
	"testing"
)

// sampleEvent builds a ring-buffer record with the C struct layout of
// bpf/tc_ingress.c: { u32 src_ip; u16 port; u16 proto; u8 kind; u8 pad;
// char server[64]; }.
func sampleEvent(kind uint8, ip uint32, port, proto uint16, server string) []byte {
	b := make([]byte, eventLen)
	binary.LittleEndian.PutUint32(b[0:4], ip)
	binary.LittleEndian.PutUint16(b[4:6], port)
	binary.LittleEndian.PutUint16(b[6:8], proto)
	b[8] = kind
	copy(b[10:eventLen], server)
	return b
}

func TestDecodeEventKinds(t *testing.T) {
	cases := []struct {
		name         string
		kind         uint8
		proto        uint16
		server       string
		wantKind     string
		wantService  string
		wantProtocol string
	}{
		{"ssh banner", kindSSH, 6, "OpenSSH_9.6p1", "banner", "ssh", "tcp"},
		{"rtsp banner", kindRTSP, 6, "RTSP/1.0 200 OK", "rtsp_banner", "rtsp", "tcp"},
		{"http banner", kindHTTP, 6, "HTTP/1.1 200 OK", "banner", "http", "tcp"},
		{"ws-discovery", kindWSDiscovery, 17, "", "wsdiscovery", "onvif", "udp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// src_ip holds raw network-order bytes; as a little-endian u32
			// the value 0x0100A8C0 is 192.168.0.1.
			ev := decodeEvent(sampleEvent(c.kind, 0x0100A8C0, 5555, c.proto, c.server))
			if ev.Source != "passive:ebpf:tc" {
				t.Errorf("Source = %q", ev.Source)
			}
			if ev.Kind != c.wantKind || ev.Protocol != c.wantProtocol {
				t.Errorf("Kind/Protocol = %q/%q, want %q/%q", ev.Kind, ev.Protocol, c.wantKind, c.wantProtocol)
			}
			if ev.RawData["service_hint"] != c.wantService {
				t.Errorf("service_hint = %q, want %q", ev.RawData["service_hint"], c.wantService)
			}
			if ev.IP != "192.168.0.1" || ev.Port != 5555 {
				t.Errorf("IP/Port = %q/%d", ev.IP, ev.Port)
			}
			if ev.Confidence != 0.6 {
				t.Errorf("Confidence = %v, want 0.6 (passive is corroborating)", ev.Confidence)
			}
			if ev.ObservedAt.IsZero() {
				t.Error("ObservedAt not set")
			}
			if c.server != "" && ev.RawData["server"] != c.server {
				t.Errorf("server = %q, want %q", ev.RawData["server"], c.server)
			}
		})
	}

	t.Run("unknown kind yields empty evidence", func(t *testing.T) {
		ev := decodeEvent(sampleEvent(99, 0x0100A8C0, 5555, 6, "whatever"))
		if ev.IP != "" || ev.Kind != "" {
			t.Fatalf("unknown kind must produce empty evidence, got %+v", ev)
		}
	})

	t.Run("short record is handled without panic", func(t *testing.T) {
		// The drain loop filters by length before calling decodeEvent; the
		// guard here documents that decodeEvent itself assumes eventLen input.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decodeEvent panicked on short input: %v", r)
			}
		}()
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b[0:4], 1)
		decodeEvent(b[:4]) // undersized: acceptable to yield garbage, not panic
	})
}

func TestTrimCString(t *testing.T) {
	if got := trimCString([]byte("abc\x00zzz")); got != "abc" {
		t.Errorf("trimCString NUL = %q", got)
	}
	if got := trimCString([]byte("abc")); got != "abc" {
		t.Errorf("trimCString full = %q", got)
	}
	if got := trimCString([]byte{0, 'x'}); got != "" {
		t.Errorf("trimCString leading NUL = %q", got)
	}
}

func TestIPString(t *testing.T) {
	// src_ip is network byte order in the event; ipString reads it
	// little-endian as the C side wrote raw bytes.
	if got := ipString(0x0100007F); got != "127.0.0.1" {
		t.Errorf("ipString = %q, want 127.0.0.1", got)
	}
	if got := ipString(0); got != "0.0.0.0" {
		t.Errorf("ipString(0) = %q", got)
	}
}

func TestProtoName(t *testing.T) {
	if protoName(6) != "tcp" || protoName(17) != "udp" {
		t.Fatal("tcp/udp mappings wrong")
	}
	if got := protoName(1); got != "ip:1" {
		t.Errorf("protoName(1) = %q", got)
	}
}
