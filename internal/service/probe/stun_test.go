// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// buildResponse crafts a Binding Response around an address attribute, the
// way a real server (or a test fake) would.
func buildResponse(t *testing.T, txID [12]byte, attrType uint16, body []byte) []byte {
	t.Helper()
	pkt := make([]byte, 20+4+len(body))
	pkt[0], pkt[1] = 0x01, 0x01 // Binding Success Response
	binary.BigEndian.PutUint16(pkt[2:], uint16(4+len(body)))
	copy(pkt[4:8], []byte{0x21, 0x12, 0xA4, 0x42})
	copy(pkt[8:20], txID[:])
	binary.BigEndian.PutUint16(pkt[20:], attrType)
	binary.BigEndian.PutUint16(pkt[22:], uint16(len(body)))
	copy(pkt[24:], body)
	return pkt
}

func xorBody(t *testing.T, ip net.IP, port int) []byte {
	t.Helper()
	cookie := uint32(stunMagicCookie)
	body := make([]byte, 8)
	body[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(body[2:], uint16(port)^(uint16(cookie>>16)))
	for i := 0; i < 4; i++ {
		body[4+i] = ip[i] ^ byte(cookie>>(24-8*i))
	}
	return body
}

func mappedBody(ip net.IP, port int) []byte {
	body := make([]byte, 8)
	body[1] = 0x01
	binary.BigEndian.PutUint16(body[2:], uint16(port))
	copy(body[4:], ip)
	return body
}

func TestBuildSTUNBindingRequest(t *testing.T) {
	req, err := BuildSTUNBindingRequest()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if req[0] != 0 || req[1] != 0x01 {
		t.Errorf("type = %x, want Binding Request 0001", req[0:2])
	}
	if binary.BigEndian.Uint32(req[4:8]) != stunMagicCookie {
		t.Errorf("magic cookie mismatch")
	}
	req2, _ := BuildSTUNBindingRequest()
	if string(req[8:]) == string(req2[8:]) {
		t.Error("transaction ids must differ between requests")
	}
}

func TestParseSTUNBindingResponse_XorMapped(t *testing.T) {
	req, _ := BuildSTUNBindingRequest()
	txID := [12]byte{}
	copy(txID[:], req[8:20])
	wantIP := net.IPv4(198, 51, 100, 7).To4()
	pkt := buildResponse(t, txID, stunAttrXorMapped, xorBody(t, wantIP, 51234))

	ip, port, err := ParseSTUNBindingResponse(pkt, txID)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ip.Equal(wantIP) {
		t.Errorf("ip = %v, want %v", ip, wantIP)
	}
	if port != 51234 {
		t.Errorf("port = %d, want 51234", port)
	}
}

func TestParseSTUNBindingResponse_MappedFallback(t *testing.T) {
	req, _ := BuildSTUNBindingRequest()
	txID := [12]byte{}
	copy(txID[:], req[8:20])
	pkt := buildResponse(t, txID, stunAttrMapped, mappedBody(net.IPv4(192, 0, 2, 99).To4(), 40001))
	ip, port, err := ParseSTUNBindingResponse(pkt, txID)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ip.String() != "192.0.2.99" || port != 40001 {
		t.Errorf("got %v:%d", ip, port)
	}
}

func TestParseSTUNBindingResponse_Rejects(t *testing.T) {
	req, _ := BuildSTUNBindingRequest()
	txID := [12]byte{}
	copy(txID[:], req[8:20])

	short := buildResponse(t, txID, stunAttrXorMapped, xorBody(t, net.IPv4(1, 2, 3, 4), 1))[:19]
	if _, _, err := ParseSTUNBindingResponse(short, txID); err == nil {
		t.Error("short packet must fail")
	}
	badType := buildResponse(t, txID, stunAttrXorMapped, xorBody(t, net.IPv4(1, 2, 3, 4), 1))
	badType[1] = 0x02
	if _, _, err := ParseSTUNBindingResponse(badType, txID); err == nil {
		t.Error("non-response type must fail")
	}
	badCookie := buildResponse(t, txID, stunAttrXorMapped, xorBody(t, net.IPv4(1, 2, 3, 4), 1))
	badCookie[4] = 0x00
	if _, _, err := ParseSTUNBindingResponse(badCookie, txID); err == nil {
		t.Error("cookie mismatch must fail")
	}
	badTx := buildResponse(t, txID, stunAttrXorMapped, xorBody(t, net.IPv4(1, 2, 3, 4), 1))
	badTx[8] ^= 0xFF
	if _, _, err := ParseSTUNBindingResponse(badTx, txID); err == nil {
		t.Error("txid mismatch must fail")
	}
	// Response without any address attribute.
	bare := make([]byte, 20)
	bare[1] = 0x01
	copy(bare[4:8], []byte{0x21, 0x12, 0xA4, 0x42})
	copy(bare[8:20], txID[:])
	if _, _, err := ParseSTUNBindingResponse(bare, txID); err == nil {
		t.Error("missing address attribute must fail")
	}
}

// TestSTUNQuery_AgainstFakeServer: a loopback UDP server answering with a
// XOR-MAPPED-ADDRESS proving the full round trip (the decode asserts the
// server SAW our real source port — the property the NAT classifier needs).
func TestSTUNQuery_AgainstFakeServer(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, rerr := server.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if n < 20 || buf[0] != 0x00 || buf[1] != 0x01 {
				continue
			}
			var txID [12]byte
			copy(txID[:], buf[8:20])
			peerIP := net.ParseIP(strings.Split(addr.String(), ":")[0]).To4()
			peerPort, _ := net.ResolveUDPAddr("udp4", addr.String())
			resp := buildResponse(t, txID, stunAttrXorMapped, xorBody(t, peerIP, peerPort.Port))
			server.WriteTo(resp, addr)
		}
	}()

	res, qerr := STUNQuery(server.LocalAddr().String(), 3*time.Second)
	if qerr != nil {
		t.Fatalf("query: %v", qerr)
	}
	if res.MappedPort == 0 || res.MappedIP != "127.0.0.1" {
		t.Errorf("result = %+v, want mapped 127.0.0.1:<ephemeral>", res)
	}
	if res.RTTms <= 0 {
		t.Errorf("rtt not measured: %+v", res)
	}
}

func TestNormalizeSTUNServer(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{"stun.cloudflare.com:3478", "stun.cloudflare.com:3478", false},
		{"stun.example.com", "stun.example.com:3478", false},
		{"203.0.113.9", "203.0.113.9:3478", false},
		{"stun:stun.example.com", "", true},
		{"stun.example.com:99999", "", true},
		{"", "", true},
		{"host with space:3478", "", true},
	}
	for _, c := range cases {
		got, err := normalizeSTUNServer(c.in)
		if c.err {
			if err == nil {
				t.Errorf("%q: expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("%q: got %q want %q", c.in, got, c.want)
		}
	}
}

func TestValidateSTUNServer(t *testing.T) {
	if !ValidateSTUNServer("stun.l.google.com:19302") {
		t.Error("valid server rejected")
	}
	if ValidateSTUNServer("https://nope") {
		t.Error("URI accepted")
	}
}

// TestDecodeMapped_Rejects covers the MAPPED-ADDRESS decoder's two negative
// branches (the XOR path has the same shape but a distinct port decode).
func TestDecodeMapped_Rejects(t *testing.T) {
	if _, _, err := decodeMapped([]byte{0x00, 0x01, 0x30, 0x39}); err == nil {
		t.Error("short body must fail")
	}
	if _, _, err := decodeMapped([]byte{0x00, 0x02, 0x30, 0x39, 192, 0, 2, 1}); err == nil {
		t.Error("non-IPv4 family must fail")
	}
}

// TestBytesEqual pins the compare helper's length and content branches.
func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte{1, 2}, []byte{1, 2}) {
		t.Error("equal slices reported different")
	}
	if bytesEqual([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Error("length mismatch reported equal")
	}
	if bytesEqual([]byte{1, 2}, []byte{1, 3}) {
		t.Error("content mismatch reported equal")
	}
}

// TestSTUNQuery_Failures covers the pre-dial rejection and the
// no-answer timeout: a valid but silent endpoint returns the deadline error
// with the diagnostic stashed on the result.
func TestSTUNQuery_Failures(t *testing.T) {
	// Unparseable endpoint rejected before any socket work.
	res, err := STUNQuery("stun:bad-uri", 50*time.Millisecond)
	if err == nil || res == nil || res.Err == "" {
		t.Fatalf("bad endpoint: res=%+v err=%v", res, err)
	}

	// A bound-then-closed UDP port answers nothing: the read deadline fires.
	silent, lerr := net.ListenPacket("udp4", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	addr := silent.LocalAddr().String()
	silent.Close()
	if res, err = STUNQuery(addr, 80*time.Millisecond); err == nil {
		t.Fatalf("silent server must time out, got %+v", res)
	} else if res.Err == "" {
		t.Error("timeout result must carry the error text")
	}
}
