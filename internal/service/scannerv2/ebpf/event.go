// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Ring-buffer event decoding, shared by both build configurations so the
// default build's CI unit-tests cover it (#493). The binary layout mirrors
// struct event in bpf/tc_ingress.c byte for byte.

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// eventLen mirrors the C struct (v4, #496): 4+2+2+1+1 + server[64] +
// opt55_raw[12] + name_raw[32] + opt55_len + dhcp_type + pad. All string
// building happens here — the BPF program writes constant-index bytes only.
const eventLen = 124

// Event kind constants — keep in sync with the enum in bpf/tc_ingress.c.
const (
	kindSSH         uint8 = 1
	kindRTSP        uint8 = 2
	kindHTTP        uint8 = 3
	kindWSDiscovery uint8 = 4
	kindDHCP        uint8 = 5
	kindTLSSNI      uint8 = 6
	kindMDNS        uint8 = 7
	kindSSDP        uint8 = 8
	kindARP         uint8 = 9
	kindND          uint8 = 10
)

// decodeEvent parses one ring-buffer record into Evidence. Unknown kinds,
// truncated records and zeroed source addresses yield an empty Evidence (no
// IP), which callers drop — decoding never panics on malformed input (#493).
// Passive evidence is corroborating only: confidence stays at 0.6.
func decodeEvent(b []byte) scannerv2.Evidence {
	if len(b) < eventLen {
		return scannerv2.Evidence{}
	}
	ip := ipString(binary.LittleEndian.Uint32(b[0:4]))
	port := int(binary.LittleEndian.Uint16(b[4:6]))
	proto := binary.LittleEndian.Uint16(b[6:8])
	kind := b[8]
	server := trimCString(b[10:74])

	var eKind, service string
	switch kind {
	case kindSSH:
		eKind, service = "banner", "ssh"
	case kindRTSP:
		eKind, service = "rtsp_banner", "rtsp"
	case kindHTTP:
		eKind, service = "banner", "http"
	case kindWSDiscovery:
		eKind, service = "wsdiscovery", "onvif"
	case kindDHCP:
		eKind, service = "dhcp", "dhcp"
	case kindTLSSNI:
		eKind, service = "tls_sni", "https"
	case kindMDNS:
		eKind, service = "mdns", "mdns"
	case kindSSDP:
		eKind, service = "ssdp", "ssdp"
	case kindARP:
		eKind, service = "arp_sighting", "arp"
	case kindND:
		eKind, service = "nd_sighting", "nd"
	default:
		return scannerv2.Evidence{}
	}
	raw := map[string]string{}
	if server != "" && eKind != "dhcp" && eKind != "nd_sighting" {
		raw["server"] = server
	}
	switch kind {
	case kindDHCP:
		if v := trimCString(b[10:74]); v != "" {
			raw["vendor_class"] = v
		}
		if n := int(b[118]); n > 0 && n <= 12 {
			raw["opt55"] = joinOptionList(b[74 : 74+n])
		}
		if b[119] > 0 {
			raw["msg_type"] = fmt.Sprintf("%d", b[119])
		}
	case kindTLSSNI:
		if server != "" {
			raw["sni"] = server
		}
	case kindMDNS:
		if q := decodeDNSWireName(b[86:118]); q != "" {
			raw["query"] = q
		}
	case kindARP, kindND:
		// Presence sightings (#497): the MAC lives in the opt55 slot (6 bytes),
		// the ARP sender IP in src_ip, the ND sender IPv6 raw in server[0:16].
		raw["mac"] = macString(b[74:80])
		if kind == kindARP {
			if b[119] == 1 {
				raw["op"] = "request"
			} else {
				raw["op"] = "reply"
			}
		} else {
			raw["ipv6"] = ipv6String(b[10:26])
			raw["icmp6_type"] = fmt.Sprintf("%d", b[119])
		}
	}
	raw["service_hint"] = service
	if kind == kindND {
		ip = "" // presence is MAC-keyed; no IPv4 to report
	}
	protocol := protoName(proto)
	switch kind {
	case kindARP:
		protocol = "arp" // no L4: the ethertype is the protocol
	case kindND:
		protocol = "icmpv6"
	}
	return scannerv2.Evidence{
		Source:     "passive:ebpf:tc",
		Kind:       eKind,
		IP:         ip,
		Port:       port,
		Protocol:   protocol,
		RawData:    raw,
		Confidence: confidenceFor(kind),
		ObservedAt: time.Now(),
	}
}

// routePassive is the drain loop's per-event decision (#497): ARP/ND presence
// sightings are facts about the network, not service evidence — they go to the
// discovery channel via the sighting callback and are never buffered for
// Probe(). ND sightings carry no IPv4 (ip stays empty) until the MAC-keyed
// discovery channel lands (#522); the callback decides what to do with them.
// Everything else buffers under the source IP as scan evidence.
func routePassive(ev scannerv2.Evidence, recent map[string][]scannerv2.Evidence, sighting func(ip, mac string)) {
	if ev.Kind == "arp_sighting" || ev.Kind == "nd_sighting" {
		if sighting != nil {
			sighting(ev.IP, ev.RawData["mac"])
		}
		return
	}
	recent[ev.IP] = append(recent[ev.IP], ev)
}

// macString renders the 6 bytes in the opt55 slot as aa:bb:cc:dd:ee:ff.
func macString(b []byte) string {
	var sb strings.Builder
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x", v)
	}
	return sb.String()
}

// ipv6String renders the 16 raw bytes of the ND sender address; an all-zero
// capture reads as "::" (the BPF read can only fail on truncated frames,
// which the program drops before emitting).
func ipv6String(b []byte) string {
	ip := make(net.IP, net.IPv6len)
	copy(ip, b)
	return ip.String()
}

// confidenceFor: DHCP carries vendor-class + parameter-list self-declaration
// and an ARP/ND sighting is a hard on-wire liveness fact from the sender
// itself (both 0.8, the same weight as the active mDNS/SSDP seeds); a TLS SNI
// is a somewhat weaker client-side hint; plain protocol presence stays
// corroborating.
func confidenceFor(kind uint8) float64 {
	switch kind {
	case kindDHCP, kindARP, kindND:
		return 0.8
	case kindTLSSNI:
		return 0.7
	default:
		return 0.6
	}
}

// protoName maps the IP protocol number recorded by the BPF program.
func protoName(p uint16) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("ip:%d", p)
	}
}

func trimCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ipString(be uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(be), byte(be>>8), byte(be>>16), byte(be>>24))
}

// joinOptionList renders a DHCP parameter request list (raw option bytes) as
// comma-joined decimal: 1,33,3,6,15... The canonical form the fingerprint
// corpus matches on.
func joinOptionList(b []byte) string {
	parts := make([]string, 0, len(b))
	for _, v := range b {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, ",")
}

// decodeDNSWireName renders length-prefixed DNS labels (the wire format the
// BPF program captures verbatim) as a dot-joined hostname. Rejects anything
// malformed: label lengths > 63 (compression pointers live there) and
// truncation without a terminating root label yield "".
func decodeDNSWireName(b []byte) string {
	var out strings.Builder
	for i := 0; i < len(b); {
		n := int(b[i])
		if n == 0 {
			return out.String()
		}
		if n > 63 || i+1+n > len(b) {
			return ""
		}
		if out.Len() > 0 {
			out.WriteByte('.')
		}
		out.Write(b[i+1 : i+1+n])
		i += 1 + n
	}
	return ""
}
