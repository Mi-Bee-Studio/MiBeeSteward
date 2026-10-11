// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// STPMIBProbe walks the BRIDGE-MIB dot1dStp subtree (STP information) to recover
// Spanning Tree Protocol topology facts: which bridge is the STP root, the
// designated root port, and each port's STP role/state (forwarding/blocking).
// This is topology metadata rather than direct adjacency, it explains why a
// physical link may carry no traffic (blocked by STP) and identifies the
// network's logical root. Evidence is emitted with protocol "STP" for the
// orchestrator; consumers can use root/designated roles to orient the topology
// view (root at the top) and port states to flag disabled edges.
package probe

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// STP-MIB OIDs (RFC 4318 / IEEE 802.1D):
//
//   - dot1dBaseBridgeAddress (1.3.6.1.2.1.17.1.1.0): scalar, the bridge's own MAC address.
//   - dot1dStpDesignatedRoot (1.3.6.1.2.1.17.2.1.0): scalar, 8 bytes - the network's
//     root bridge ID (2 priority bytes + the root bridge MAC).
//   - dot1dStpPortDesignatedBridge (1.3.6.1.2.1.17.2.2.1.15): OCTET STRING (8 bytes) per
//     bridge port. First 2 bytes = bridge priority (big-endian uint16), next 6 bytes = bridge
//     MAC. The OID index is the bridge port number (1-based integer).
const (
	oidDot1dBaseBridgeAddress       = "1.3.6.1.2.1.17.1.1.0"
	oidDot1dStpDesignatedRoot       = "1.3.6.1.2.1.17.2.1.0"
	oidDot1dStpPortDesignatedBridge = "1.3.6.1.2.1.17.2.2.1.15"
	oidDot1dStpPortRole             = "1.3.6.1.2.1.17.2.2.1.18"
)

// stpRoleName maps the dot1dStpPortRole enum to its name; unknown values
// render numerically so a future MIB extension still surfaces.
func stpRoleName(v int) string {
	switch v {
	case 1:
		return "disabled"
	case 2:
		return "alternate"
	case 3:
		return "backup"
	case 4:
		return "root"
	case 5:
		return "designated"
	default:
		return strconv.Itoa(v)
	}
}

// STPMIBProbe walks the STP-MIB dot1dStpPortTable on bridges/switches that speak
// SNMP. It discovers the designated bridge for each port, the bridge that is
// the STP root for that segment.
//
// Output: one "neighbor" Evidence per unique designated bridge, carrying the
// neighbor's MAC (the merge key) + the local bridge port. Only emits for ports
// whose designated bridge differs from the local bridge's own MAC (self-loops
// are skipped).
//
// Confidence: 0.7, STP topology is indirect inference (the designated bridge
// is not necessarily directly connected, it could be multiple hops away).
//
// Name: "active:stp_mib".
type STPMIBProbe struct {
	logger *slog.Logger
}

// NewSTPMIBProbe returns an STP-MIB probe. logger may be nil.
func NewSTPMIBProbe(logger *slog.Logger) *STPMIBProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &STPMIBProbe{logger: logger}
}

func (p *STPMIBProbe) Name() string { return "active:stp_mib" }

// Probe walks dot1dStpPortDesignatedBridge on ip:161. hint.Community/hint.Timeout
// apply, and a bound v3 credential in hint.SNMPCredential routes the walk
// through SNMPv3.
func (p *STPMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	snmp, err := connectSNMPWithRetries(ip, hint, gosnmp.Version2c, 1)
	if err != nil {
		return nil, nil // unreachable: not an error, just no topology data
	}
	// Note: we keep the connection open for the port-name resolution walk below

	// One Get for both scalars: local bridge MAC (dot1dBaseBridgeAddress.0)
	// and the network's root bridge ID (dot1dStpDesignatedRoot.0, #525). The
	// root scalar may be absent on ancient agents — tolerate a short reply.
	scalarResult, err := snmp.Get([]string{oidDot1dBaseBridgeAddress, oidDot1dStpDesignatedRoot})
	if err != nil || len(scalarResult.Variables) == 0 {
		snmp.Close()
		return nil, nil
	}
	bridgeAddrBytes, ok := scalarResult.Variables[0].Value.([]byte)
	if !ok || len(bridgeAddrBytes) != 6 {
		snmp.Close()
		return nil, nil
	}
	localBridgeMAC := formatMAC(bridgeAddrBytes)
	rootBridgeMAC := ""
	if len(scalarResult.Variables) > 1 {
		if rootBytes, rok := scalarResult.Variables[1].Value.([]byte); rok && len(rootBytes) == 8 {
			rootBridgeMAC = extractBridgeMACFromDesignatedBridge(rootBytes)
		}
	}

	// Walk dot1dStpPortDesignatedBridge: collect {bridgePort → designated bridge MAC}.
	// Deduplicate by designated bridge MAC, keeping the first occurrence's port.
	type stpEntry struct {
		port          int
		designatedMAC string
	}
	var entries []stpEntry
	seenMACs := make(map[string]bool)

	walkErr := snmp.Walk(oidDot1dStpPortDesignatedBridge, func(pdu gosnmp.SnmpPDU) error {
		portStr := indexSuffix(pdu.Name, oidDot1dStpPortDesignatedBridge)
		if portStr == "" {
			return nil
		}
		port := gosnmpToInt(portStr)
		if port <= 0 {
			return nil
		}
		// Extract designated bridge MAC from the 8-byte OCTET STRING.
		b, valOK := pdu.Value.([]byte)
		if !valOK || len(b) != 8 {
			return nil
		}
		designatedMAC := extractBridgeMACFromDesignatedBridge(b)
		if designatedMAC == "" {
			return nil
		}
		// Skip if the designated bridge is the local bridge itself (self-loop).
		if designatedMAC == localBridgeMAC {
			return nil
		}
		// Deduplicate by designated bridge MAC (first occurrence wins).
		if seenMACs[designatedMAC] {
			return nil
		}
		seenMACs[designatedMAC] = true
		entries = append(entries, stpEntry{port: port, designatedMAC: designatedMAC})
		return nil
	})
	if walkErr != nil {
		snmp.Close()
		return nil, nil // STP-MIB unsupported
	}

	// Port roles (#525): bridge port → dot1dStpPortRole enum. Best-effort —
	// an agent without the column keeps the probe working, roles just absent.
	portRoles := make(map[int]int)
	_ = snmp.Walk(oidDot1dStpPortRole, func(pdu gosnmp.SnmpPDU) error {
		portStr := indexSuffix(pdu.Name, oidDot1dStpPortRole)
		if portStr == "" {
			return nil
		}
		port := gosnmpToInt(portStr)
		if port <= 0 {
			return nil
		}
		if v, vok := gosnmpToIntValue(pdu.Value); vok {
			portRoles[port] = v
		}
		return nil
	})

	// No designated-bridge rows and no root fact: STP not in play here.
	if len(entries) == 0 && rootBridgeMAC == "" && len(portRoles) == 0 {
		snmp.Close()
		return nil, nil
	}

	// Resolve port names via IF-MIB (bridge port → ifIndex → ifName).
	// If it fails, we fall back to numeric port numbers.
	portNames := ResolvePortNames(snmp, p.logger)

	var evidence []scannerv2.Evidence

	// Device-level STP facts (#525): the root-orientation data the graph
	// reads (is_root replaces root-detection heuristics). Emitted whenever
	// the dot1dStp walk produced anything, even on the root bridge itself
	// where every designated bridge is self and no edge survives.
	if rootBridgeMAC != "" || len(portRoles) > 0 {
		ports := make([]string, 0, len(portRoles))
		for _, port := range sortedPortKeys(portRoles) {
			key := strconv.Itoa(port)
			if name, nok := portNames[port]; nok && name != "" {
				key = name
			}
			ports = append(ports, key+"="+stpRoleName(portRoles[port]))
		}
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:stp_mib",
			Kind:       "stp",
			IP:         ip,
			Protocol:   "snmp",
			Confidence: 0.9,
			ObservedAt: time.Now().UTC(),
			RawData: map[string]string{
				"bridge_mac":      localBridgeMAC,
				"root_bridge_mac": rootBridgeMAC,
				"is_root":         strconv.FormatBool(rootBridgeMAC != "" && rootBridgeMAC == localBridgeMAC),
				"ports":           strings.Join(ports, ","),
			},
		})
	}

	// Neighbor edges: one "neighbor" per unique designated bridge MAC, the
	// port's STP role riding along (#525).
	for _, entry := range entries {
		localPort := strconv.Itoa(entry.port)
		if name, ok := portNames[entry.port]; ok && name != "" {
			localPort = name
		}
		raw := map[string]string{
			"neighbor_mac": entry.designatedMAC,
			"protocol":     "STP",
			"local_port":   localPort,
		}
		if role, rok := portRoles[entry.port]; rok {
			raw["port_role"] = stpRoleName(role)
		}
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:stp_mib",
			Kind:       "neighbor",
			IP:         ip,
			Confidence: 0.7,
			ObservedAt: time.Now().UTC(),
			RawData:    raw,
		})
	}
	snmp.Close()
	return evidence, nil
}

// gosnmpToIntValue pulls an INTEGER out of a PDU value (gosnmp delivers
// integers as int for Integer/Counter/Gauge types).
func gosnmpToIntValue(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	default:
		return 0, false
	}
}

// sortedPortKeys returns the bridge-port numbers in ascending order so the
// rendered ports string is stable across scans.
func sortedPortKeys(m map[int]int) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// extractBridgeMACFromDesignatedBridge extracts the MAC address from an 8-byte
// dot1dStpPortDesignatedBridge value. The format is:
//
//	bytes 0-1: bridge priority (big-endian uint16, ignored)
//	bytes 2-7: bridge MAC (6 bytes)
//
// Returns "" if the input is not exactly 8 bytes.
func extractBridgeMACFromDesignatedBridge(b []byte) string {
	if len(b) != 8 {
		return ""
	}
	return formatMAC(b[2:])
}
