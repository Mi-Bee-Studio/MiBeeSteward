// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// RouteMIBProbe walks the SNMP ipRouteTable (#528): every route the device
// holds, as dest-CIDR + next-hop + egress ifIndex + protocol. One
// "route"-kind evidence row per non-direct route with a unicast next hop; the
// center materializes route-table topology edges from them (router -> next
// hop device, the answer to "how do these segments interconnect" for hops
// beyond directly-connected LANs).
//
// Direct routes (type 3, next hop 0.0.0.0) are skipped: the connected-subnet
// fact is already carried by the interface census (#529) and per-network
// presence (#526).
//
// Name: "active:route_mib".
package probe

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// ipRouteTable OIDs (RFC 1213), all indexed by the route destination IP
// encoded as dotted octets in the OID suffix:
//
//   - ipRouteDest (4.21.1.1): the destination network address.
//   - ipRouteIfIndex (4.21.1.2): egress interface.
//   - ipRouteNextHop (4.21.1.7): the next hop, 0.0.0.0 for direct routes.
//   - ipRouteType (4.21.1.8): 1 other, 2 invalid, 3 direct, 4 indirect.
//   - ipRouteProto (4.21.1.9): local|netmgmt|icmp|egp|ggp|hello|rip|isIs|...
//   - ipRouteMask (4.21.1.11): the destination network mask.
const (
	oidIpRouteDest    = "1.3.6.1.2.1.4.21.1.1"
	oidIpRouteIfIndex = "1.3.6.1.2.1.4.21.1.2"
	oidIpRouteNextHop = "1.3.6.1.2.1.4.21.1.7"
	oidIpRouteType    = "1.3.6.1.2.1.4.21.1.8"
	oidIpRouteProto   = "1.3.6.1.2.1.4.21.1.9"
	oidIpRouteMask    = "1.3.6.1.2.1.4.21.1.11"
)

// RouteMIBProbe collects the routing table via SNMP.
type RouteMIBProbe struct {
	logger *slog.Logger
}

// NewRouteMIBProbe returns a route-table probe. logger may be nil.
func NewRouteMIBProbe(logger *slog.Logger) *RouteMIBProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &RouteMIBProbe{logger: logger}
}

func (p *RouteMIBProbe) Name() string { return "active:route_mib" }

// Probe walks ipRouteTable on ip:161.
func (p *RouteMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	snmp, err := connectSNMPWithRetries(ip, hint, gosnmp.Version2c, 1)
	if err != nil {
		return nil, nil
	}

	dests := make(map[string]string) // route key (dest IP octets) -> dotted dest
	nextHops := make(map[string]string)
	types := make(map[string]int)
	protos := make(map[string]string)
	masks := make(map[string]string)
	ifIdx := make(map[string]int)

	collect := func(oid string, sink func(key string, pdu gosnmp.SnmpPDU)) {
		_ = snmp.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
			key := indexSuffix(pdu.Name, oid)
			if key != "" {
				sink(key, pdu)
			}
			return nil
		})
	}

	collect(oidIpRouteDest, func(key string, pdu gosnmp.SnmpPDU) {
		if b, ok := pdu.Value.([]byte); ok {
			dests[key] = octetsToDotted(b)
		}
	})
	collect(oidIpRouteNextHop, func(key string, pdu gosnmp.SnmpPDU) {
		if b, ok := pdu.Value.([]byte); ok {
			nextHops[key] = octetsToDotted(b)
		}
	})
	collect(oidIpRouteMask, func(key string, pdu gosnmp.SnmpPDU) {
		if b, ok := pdu.Value.([]byte); ok {
			masks[key] = octetsToDotted(b)
		}
	})
	collect(oidIpRouteType, func(key string, pdu gosnmp.SnmpPDU) {
		if v, ok := gosnmpToIntValue(pdu.Value); ok {
			types[key] = v
		}
	})
	collect(oidIpRouteProto, func(key string, pdu gosnmp.SnmpPDU) {
		if s, ok := octetStringValue(pdu); ok {
			protos[key] = s
		} else if v, ok := gosnmpToIntValue(pdu.Value); ok {
			protos[key] = strconv.Itoa(v)
		}
	})
	collect(oidIpRouteIfIndex, func(key string, pdu gosnmp.SnmpPDU) {
		if v, ok := gosnmpToIntValue(pdu.Value); ok {
			ifIdx[key] = v
		}
	})
	snmp.Close()

	if len(dests) == 0 {
		return nil, nil // no routing table via SNMP
	}

	var evidence []scannerv2.Evidence
	for key, dest := range dests {
		if types[key] == 3 { // direct: connected-subnet fact lives elsewhere
			continue
		}
		hop := nextHops[key]
		if hop == "" || hop == "0.0.0.0" {
			continue
		}
		mask := masks[key]
		if !strings.Contains(dest, "/") && mask != "" {
			dest = dest + "/" + strconv.Itoa(maskBits(mask))
		}
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:route_mib",
			Kind:       "route",
			IP:         ip,
			Protocol:   "snmp",
			Confidence: 0.9,
			ObservedAt: time.Now().UTC(),
			RawData: map[string]string{
				"dest":     dest,
				"next_hop": hop,
				"if_index": strconv.Itoa(ifIdx[key]),
				"proto":    protos[key],
			},
		})
	}
	return evidence, nil
}

// octetsToDotted renders 4 raw octets as a dotted IPv4 string.
func octetsToDotted(b []byte) string {
	if len(b) != 4 {
		return ""
	}
	parts := make([]string, 4)
	for i, v := range b {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, ".")
}

// maskBits converts a dotted netmask to its prefix length (bits set).
func maskBits(mask string) int {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return 0
	}
	bits := 0
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		switch v {
		case 255:
			bits += 8
		case 254:
			bits += 7
		case 252:
			bits += 6
		case 248:
			bits += 5
		case 240:
			bits += 4
		case 224:
			bits += 3
		case 192:
			bits += 2
		case 128:
			bits += 1
		}
	}
	return bits
}
