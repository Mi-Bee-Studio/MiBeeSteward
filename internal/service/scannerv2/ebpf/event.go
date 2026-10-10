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
	default:
		return scannerv2.Evidence{}
	}
	raw := map[string]string{}
	if server != "" && eKind != "dhcp" {
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
	}
	raw["service_hint"] = service
	return scannerv2.Evidence{
		Source:     "passive:ebpf:tc",
		Kind:       eKind,
		IP:         ip,
		Port:       port,
		Protocol:   protoName(proto),
		RawData:    raw,
		Confidence: confidenceFor(kind),
		ObservedAt: time.Now(),
	}
}

// confidenceFor: DHCP carries vendor-class + parameter-list self-declaration
// (0.8, the same weight as the active mDNS/SSDP seeds); a TLS SNI is a
// somewhat weaker client-side hint; plain protocol presence stays
// corroborating.
func confidenceFor(kind uint8) float64 {
	switch kind {
	case kindDHCP:
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
