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
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// eventLen mirrors the C struct: 4 + 2 + 2 + 1 + 1(padding) + 64.
const eventLen = 74

// Event kind constants — keep in sync with the enum in bpf/tc_ingress.c.
const (
	kindSSH         uint8 = 1
	kindRTSP        uint8 = 2
	kindHTTP        uint8 = 3
	kindWSDiscovery uint8 = 4
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
	server := trimCString(b[10:eventLen])

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
	default:
		return scannerv2.Evidence{}
	}
	raw := map[string]string{}
	if server != "" {
		raw["server"] = server
	}
	raw["service_hint"] = service
	return scannerv2.Evidence{
		Source:     "passive:ebpf:tc",
		Kind:       eKind,
		IP:         ip,
		Port:       port,
		Protocol:   protoName(proto),
		RawData:    raw,
		Confidence: 0.6, // passive is corroborating, not authoritative
		ObservedAt: time.Now(),
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
