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

// Event layout v3 (#496): header + server[64] + opt55_raw[16] + name_raw[48]
// + opt55_len + dhcp_type. All rendering (opt55 decimal join, DNS label
// join) happens in the Go decoder; the BPF side writes raw bytes only.
func TestDecodeEventV3Kinds(t *testing.T) {
	mk := func(kind uint8, ip uint32, port, proto uint16, str string, opt55 []byte, name []byte, dhcpType uint8) []byte {
		b := make([]byte, eventLen)
		binary.LittleEndian.PutUint32(b[0:4], ip)
		binary.LittleEndian.PutUint16(b[4:6], port)
		binary.LittleEndian.PutUint16(b[6:8], proto)
		b[8] = kind
		copy(b[10:74], str)
		copy(b[74:86], opt55)
		copy(b[86:118], name)
		b[118] = byte(len(opt55))
		b[119] = dhcpType
		return b
	}
	t.Run("dhcp", func(t *testing.T) {
		ev := decodeEvent(mk(5, 0x0100A8C0, 68, 17, "android-dhcp-13",
			[]byte{1, 33, 3, 6, 15, 26, 28, 51, 58, 59}, nil, 1))
		if ev.Kind != "dhcp" {
			t.Fatalf("Kind = %q", ev.Kind)
		}
		if ev.RawData["vendor_class"] != "android-dhcp-13" {
			t.Errorf("vendor_class = %q", ev.RawData["vendor_class"])
		}
		if ev.RawData["opt55"] != "1,33,3,6,15,26,28,51,58,59" {
			t.Errorf("opt55 = %q", ev.RawData["opt55"])
		}
		if ev.RawData["msg_type"] != "1" {
			t.Errorf("msg_type = %q", ev.RawData["msg_type"])
		}
		if ev.Confidence != 0.8 {
			t.Errorf("dhcp self-declaration confidence = %v", ev.Confidence)
		}
	})
	t.Run("tls_sni", func(t *testing.T) {
		ev := decodeEvent(mk(6, 0x0100A8C0, 443, 6, "blog.mickeyzzc.tech", nil, nil, 0))
		if ev.Kind != "tls_sni" || ev.RawData["sni"] != "blog.mickeyzzc.tech" {
			t.Fatalf("Kind/sni = %q/%v", ev.Kind, ev.RawData["sni"])
		}
		if ev.Confidence != 0.7 {
			t.Errorf("sni confidence = %v", ev.Confidence)
		}
	})
	t.Run("mdns wire name joins", func(t *testing.T) {
		// wire format for "rig-sensor._tcp.local": len-prefixed labels
		wire := []byte{10}
		wire = append(wire, "rig-sensor"...)
		wire = append(wire, 4)
		wire = append(wire, "_tcp"...)
		wire = append(wire, 5)
		wire = append(wire, "local"...)
		ev := decodeEvent(mk(7, 0x0100A8C0, 5353, 17, "", nil, wire, 0))
		if ev.Kind != "mdns" || ev.RawData["query"] != "rig-sensor._tcp.local" {
			t.Fatalf("Kind/query = %q/%v", ev.Kind, ev.RawData["query"])
		}
	})
	t.Run("mdns rejects compression pointer", func(t *testing.T) {
		ev := decodeEvent(mk(7, 0x0100A8C0, 5353, 17, "", nil, []byte{0xc0, 0x0c}, 0))
		if ev.RawData["query"] != "" {
			t.Fatalf("compression pointer must not render, got %q", ev.RawData["query"])
		}
	})
	t.Run("ssdp passive", func(t *testing.T) {
		ev := decodeEvent(mk(8, 0x0100A8C0, 1900, 17, "", nil, nil, 0))
		if ev.Kind != "ssdp" {
			t.Fatalf("Kind = %q", ev.Kind)
		}
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
