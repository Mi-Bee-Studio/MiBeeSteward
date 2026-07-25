// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build WITH_ARPSCAN

package discovery

import (
	"net"
	"testing"
)

// TestBuildARPRequestLayout verifies the constant fields of a freshly built
// who-has frame: ethertype, ARP header fields, op=request, and the sender
// MAC/IP pinned to our NIC. The target IP/MAC are set per-IP by
// fillARPRequestTarget (tested separately).
func TestBuildARPRequestLayout(t *testing.T) {
	srcMAC := [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}
	srcIP := [4]byte{192, 168, 63, 101}
	f := buildARPRequest(srcMAC, srcIP)

	if len(f) != 42 {
		t.Fatalf("frame length = %d, want 42", len(f))
	}
	// Ethertype ARP at [12..13].
	if f[12] != 0x08 || f[13] != 0x06 {
		t.Errorf("ethertype = %02x%02x, want 0806", f[12], f[13])
	}
	// ARP htype=1, ptype=0x0800, hlen=6, plen=4.
	if f[14] != 0x00 || f[15] != 0x01 {
		t.Errorf("htype = %02x%02x, want 0001 (Ethernet)", f[14], f[15])
	}
	if f[16] != 0x08 || f[17] != 0x00 {
		t.Errorf("ptype = %02x%02x, want 0800 (IPv4)", f[16], f[17])
	}
	if f[18] != 6 || f[19] != 4 {
		t.Errorf("hlen/plen = %d/%d, want 6/4", f[18], f[19])
	}
	// Opcode = request (1).
	if f[20] != 0x00 || f[21] != arpOpRequest {
		t.Errorf("opcode = %02x%02x, want 0001 (request)", f[20], f[21])
	}
	// Sender HW + sender proto = our NIC.
	if got := net.HardwareAddr(f[22:28]).String(); got != "aa:bb:cc:00:11:22" {
		t.Errorf("sender MAC = %s, want aa:bb:cc:00:11:22", got)
	}
	if got := net.IP(f[28:32]).String(); got != "192.168.63.101" {
		t.Errorf("sender IP = %s, want 192.168.63.101", got)
	}
	// Target HW addr must be zero in the template (unknown — that's the question).
	for i, b := range f[32:38] {
		if b != 0 {
			t.Errorf("target HW byte [%d] = %02x, want 00 (template must zero target HW)", i, b)
		}
	}
}

// TestFillARPRequestTarget verifies per-IP target + broadcast dst fill. It must
// not mutate the template (each frame is an independent copy).
func TestFillARPRequestTarget(t *testing.T) {
	srcMAC := [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}
	srcIP := [4]byte{192, 168, 63, 101}
	tmpl := buildARPRequest(srcMAC, srcIP)

	bcast := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	tgt := [4]byte{192, 168, 63, 34}
	f := fillARPRequestTarget(tmpl, bcast, srcMAC, srcIP, tgt)

	// Ethernet dst = broadcast.
	if got := net.HardwareAddr(f[0:6]).String(); got != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("dst MAC = %s, want broadcast", got)
	}
	// Target IP = 192.168.63.34.
	if got := net.IP(f[38:42]).String(); got != "192.168.63.34" {
		t.Errorf("target IP = %s, want 192.168.63.34", got)
	}
	// Template unchanged: its dst is still zero (it was never the broadcast).
	for i, b := range tmpl[0:6] {
		if b != 0 {
			t.Errorf("template dst byte [%d] = %02x — fillARPRequestTarget must not mutate the template", i, b)
		}
	}
}

// TestParseARPReply covers the inbound-frame parser: a well-formed reply yields
// the sender IP+MAC; requests, wrong ethertype, and truncated frames are
// rejected. This is the function that decides what becomes a NewHostEvent.
func TestParseARPReply(t *testing.T) {
	// Build a synthetic ARP reply (op=2) with a known sender.
	reply := make([]byte, 42)
	// ethertype ARP
	reply[12] = 0x08
	reply[13] = 0x06
	// htype/ptype/hlen/plen
	reply[14], reply[15] = 0x00, 0x01
	reply[16], reply[17] = 0x08, 0x00
	reply[18], reply[19] = 6, 4
	// op = reply
	reply[20], reply[21] = 0x00, arpOpReply
	copy(reply[22:28], []byte{0xdc, 0xa6, 0x32, 0x12, 0x2a, 0x4b}) // sender MAC
	copy(reply[28:32], []byte{192, 168, 63, 34})                   // sender IP

	ip, mac, ok := parseARPReply(reply)
	if !ok {
		t.Fatal("parseARPReply rejected a valid reply")
	}
	if ip != "192.168.63.34" {
		t.Errorf("ip = %s, want 192.168.63.34", ip)
	}
	if mac != "dc:a6:32:12:2a:4b" {
		t.Errorf("mac = %s, want dc:a6:32:12:2a:4b", mac)
	}

	// op = request → rejected (we only learn from replies).
	req := append([]byte(nil), reply...)
	req[20], req[21] = 0x00, arpOpRequest
	if _, _, ok := parseARPReply(req); ok {
		t.Error("parseARPReply accepted a request frame; should only accept replies")
	}

	// wrong ethertype → rejected.
	notarp := append([]byte(nil), reply...)
	notarp[12], notarp[13] = 0x08, 0x00 // IPv4
	if _, _, ok := parseARPReply(notarp); ok {
		t.Error("parseARPReply accepted a non-ARP frame")
	}

	// truncated → rejected.
	if _, _, ok := parseARPReply(reply[:20]); ok {
		t.Error("parseARPReply accepted a truncated frame")
	}
}

// TestSubnetHostIPs verifies the /24 host expansion excludes network + broadcast
// and returns exactly the usable host range. A /24 has 254 hosts (1..254).
func TestSubnetHostIPs(t *testing.T) {
	ips := subnetHostIPs("192.168.63.0/24")
	if len(ips) != 254 {
		t.Fatalf("/24 host count = %d, want 254", len(ips))
	}
	// First host must be .1, last must be .254.
	if got := ips[0].String(); got != "192.168.63.1" {
		t.Errorf("first host = %s, want 192.168.63.1", got)
	}
	if got := ips[253].String(); got != "192.168.63.254" {
		t.Errorf("last host = %s, want 192.168.63.254", got)
	}
	// Network (.0) and broadcast (.255) must be absent.
	for _, ip := range ips {
		s := ip.String()
		if s == "192.168.63.0" || s == "192.168.63.255" {
			t.Errorf("found reserved host %s in expansion", s)
		}
	}
}

// TestSubnetHostIPsSmallCIDRs checks the /31 (point-to-point, RFC 3021) and /32
// (single host) edge cases: both are returned as-is, no network/broadcast carve-out.
func TestSubnetHostIPsSmallCIDRs(t *testing.T) {
	// /31 — RFC 3021 treats both addresses as usable.
	if ips := subnetHostIPs("10.0.0.0/31"); len(ips) != 1 {
		t.Errorf("/31 host count = %d, want 1 (the .0)", len(ips))
	}
	// /32 — single host.
	if ips := subnetHostIPs("10.0.0.5/32"); len(ips) != 1 || ips[0].String() != "10.0.0.5" {
		t.Errorf("/32 expansion = %v, want [10.0.0.5]", ips)
	}
	// Invalid CIDR → nil.
	if ips := subnetHostIPs("not-a-cidr"); ips != nil {
		t.Errorf("invalid CIDR returned %v, want nil", ips)
	}
	// IPv6 → nil (ARP is IPv4-only).
	if ips := subnetHostIPs("2001:db8::/32"); ips != nil {
		t.Errorf("IPv6 CIDR returned %v, want nil (ARP is IPv4-only)", ips)
	}
}
