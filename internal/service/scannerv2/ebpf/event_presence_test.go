// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package ebpf

import (
	"encoding/binary"
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

// presenceEvent builds an ARP/ND record per the #497 field mapping:
// ARP: src_ip = sender IPv4, opt55_raw[0:6] = sender MAC, dhcp_type = op
// (1 request / 2 reply). ND: server[0:16] = sender IPv6, opt55_raw[0:6] =
// Ethernet source MAC, dhcp_type = ICMPv6 type, proto = 58.
func presenceEvent(kind uint8, ip uint32, mac []byte, ipv6 []byte, typeByte uint8, proto uint16) []byte {
	b := make([]byte, eventLen)
	binary.LittleEndian.PutUint32(b[0:4], ip)
	binary.LittleEndian.PutUint16(b[6:8], proto)
	b[8] = kind
	copy(b[10:26], ipv6)
	copy(b[74:80], mac)
	b[118] = 6
	b[119] = typeByte
	return b
}

func TestDecodeArpSighting(t *testing.T) {
	// sender 192.168.0.50, MAC 02:81:48:4e:d5:99, op = request
	ev := decodeEvent(presenceEvent(kindARP, 0x3200A8C0,
		[]byte{0x02, 0x81, 0x48, 0x4e, 0xd5, 0x99}, nil, 1, 0))
	if ev.Kind != "arp_sighting" {
		t.Fatalf("Kind = %q", ev.Kind)
	}
	if ev.IP != "192.168.0.50" {
		t.Errorf("IP = %q", ev.IP)
	}
	if ev.Protocol != "arp" {
		t.Errorf("Protocol = %q", ev.Protocol)
	}
	if ev.RawData["mac"] != "02:81:48:4e:d5:99" {
		t.Errorf("mac = %q", ev.RawData["mac"])
	}
	if ev.RawData["op"] != "request" {
		t.Errorf("op = %q", ev.RawData["op"])
	}
	if ev.Confidence != 0.8 {
		t.Errorf("presence confidence = %v", ev.Confidence)
	}
}

func TestDecodeNdSighting(t *testing.T) {
	// fe80::101a:202b with an Ethernet source MAC, neighbor solicitation.
	ipv6 := make([]byte, 16)
	ipv6[0], ipv6[1] = 0xfe, 0x80
	ipv6[14], ipv6[15] = 0x20, 0x2b
	ipv6[12], ipv6[13] = 0x10, 0x1a
	ev := decodeEvent(presenceEvent(kindND, 0,
		[]byte{0x02, 0x81, 0x48, 0x4e, 0xd5, 0x99}, ipv6, 135, 58))
	if ev.Kind != "nd_sighting" {
		t.Fatalf("Kind = %q", ev.Kind)
	}
	if ev.RawData["ipv6"] != "fe80::101a:202b" {
		t.Errorf("ipv6 = %q", ev.RawData["ipv6"])
	}
	if ev.RawData["mac"] != "02:81:48:4e:d5:99" {
		t.Errorf("mac = %q", ev.RawData["mac"])
	}
	if ev.RawData["icmp6_type"] != "135" {
		t.Errorf("icmp6_type = %q", ev.RawData["icmp6_type"])
	}
	if ev.Protocol != "icmpv6" {
		t.Errorf("Protocol = %q", ev.Protocol)
	}
}

// routePassive is the drain-loop's routing decision: presence sightings go to
// the discovery channel (never buffered as scan evidence); ND sightings carry
// no IPv4, so their IP is empty until the MAC-keyed channel lands (#522).
func TestRoutePassivePresence(t *testing.T) {
	var seen []string
	sighting := func(ip, mac string) { seen = append(seen, ip+"/"+mac) }
	recent := map[string][]scannerv2.Evidence{}

	arp := decodeEvent(presenceEvent(kindARP, 0x3200A8C0, []byte{2, 0x81, 0x48, 0x4e, 0xd5, 0x99}, nil, 1, 0))
	routePassive(arp, recent, sighting)
	nd := decodeEvent(presenceEvent(kindND, 0, []byte{2, 0x81, 0x48, 0x4e, 0xd5, 0x99}, make([]byte, 16), 136, 58))
	routePassive(nd, recent, sighting)
	dhcp := decodeEvent(sampleEvent(kindDHCP, 0x0100A8C0, 68, 17, "android-dhcp-13"))
	routePassive(dhcp, recent, sighting)

	if len(seen) != 2 {
		t.Fatalf("sightings = %v, want arp + nd", seen)
	}
	if seen[0] != "192.168.0.50/02:81:48:4e:d5:99" {
		t.Errorf("arp sighting = %q", seen[0])
	}
	if seen[1] != "/02:81:48:4e:d5:99" {
		t.Errorf("nd sighting ip should be empty (MAC-keyed channel pending), got %q", seen[1])
	}
	if len(recent["192.168.0.1"]) != 1 || recent["192.168.0.1"][0].Kind != "dhcp" {
		t.Errorf("dhcp evidence should buffer under its IP, got %+v", recent)
	}
	if _, buffered := recent[""]; buffered {
		t.Errorf("ND sighting must not buffer under the empty IP key")
	}
}
