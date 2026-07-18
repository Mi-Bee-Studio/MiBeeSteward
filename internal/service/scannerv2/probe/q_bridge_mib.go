// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// QBridgeMIBProbe walks the IEEE 802.1Q (Q-BRIDGE) MIB — primarily
// dot1qTpFdbPort (1.2.840.10006.300.43.1.3.2) — to map learned MAC addresses to
// the bridge port (and VLAN) they were learned on. This is the VLAN-aware
// successor to the older BRIDGE-MIB dot1dTpFdbPort probe: where BRIDGE-MIB only
// sees the default VLAN, Q-BRIDGE-MIB sees per-VLAN forwarding tables, so it
// recovers L2 adjacency on tagged/inter-VLAN topologies that BRIDGE-MIB misses.
// The resolved (port, MAC) pairs feed the orchestrator's device_neighbors
// pipeline as protocol "Q-BRIDGE" edges, with ifName resolution turning the
// numeric port into a human-readable interface name.
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

// Q-BRIDGE-MIB OID subtrees (RFC 4363):
//
//   - dot1qTpFdbTable (1.3.6.1.2.1.17.7.1.2.2.1): the per-VLAN forwarding database.
//     Indexed by <VLAN>.<MAC-address>, where VLAN is 1-2 octets and MAC is 6 octets.
//     1.3.6.1.2.1.17.7.1.2.2.1.2 = dot1qTpFdbPort (the bridge port number for that MAC)
//
// By walking dot1qTpFdbPort we get every learned MAC per VLAN; its sibling
// dot1qTpFdbAddress (the MAC itself) is redundant because the OID index contains it.
const (
	oidDot1qTpFdbPort = "1.3.6.1.2.1.17.7.1.2.2.1.2" // bridge port number (int) per VLAN+MAC
)

// QBridgeMIBProbe walks the Q-BRIDGE-MIB forwarding database (dot1qTpFdbTable)
// on VLAN-aware switches/bridges that speak SNMP. It discovers which MAC addresses
// are visible behind each port, similar to Bridge-MIB but with per-VLAN granularity.
//
// The OID index format is <VLAN>.<MAC-octets>, where VLAN can be 1-2 subidentifiers
// and MAC is always 6 subidentifiers. We skip the VLAN prefix and extract the MAC
// from the last 6 integers.
//
// Output: one "neighbor" Evidence per learned MAC, carrying the neighbor's MAC
// (the merge key) + the local bridge port. The orchestrator's neighbor-extract
// step turns these into device_neighbors rows via RecordNeighbors.
//
// Only devices acting as VLAN-aware bridges/switches have a populated FDB; endpoints
// (cameras, servers) return nothing and the probe is a no-op for them.
//
// Name: "active:q_bridge_mib".
type QBridgeMIBProbe struct {
	logger *slog.Logger
}

// NewQBridgeMIBProbe returns a Q-BRIDGE-MIB probe. logger may be nil.
func NewQBridgeMIBProbe(logger *slog.Logger) *QBridgeMIBProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &QBridgeMIBProbe{logger: logger}
}

func (p *QBridgeMIBProbe) Name() string { return "active:q_bridge_mib" }

// Probe walks dot1qTpFdbTable on ip:161. hint.Community/hint.Timeout apply.
func (p *QBridgeMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	community := hint.Community
	if community == "" {
		community = "public"
	}
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}
	if err := snmp.Connect(); err != nil {
		return nil, nil // unreachable — not an error, just no topology data
	}
	// Note: we keep the connection open for the port-name resolution walk below

	// Walk the FDB: collect {MAC-octet-index → port-number}.
	// The OID index for dot1qTpFdbTable is <VLAN>.<MAC-octets> (e.g. 1.170.187.204.221.238.255),
	// where VLAN is 1-2 octets and MAC is 6 octets. We skip the VLAN prefix to extract the MAC.
	portByMacIdx := map[string]int{}
	var macIndices []string

	walkErr := snmp.Walk(oidDot1qTpFdbPort, func(pdu gosnmp.SnmpPDU) error {
		// pdu.Name = full OID including the VLAN+MAC index suffix.
		// pdu.Value = the bridge port number (integer).
		fullIndex := indexSuffix(pdu.Name, oidDot1qTpFdbPort)
		if fullIndex == "" {
			return nil
		}
		// Extract MAC from the index: skip VLAN prefix (everything before last 6 integers)
		macIdx := extractMACFromVLANIndex(fullIndex)
		if macIdx == "" {
			return nil
		}
		port := gosnmpToInt(pdu.Value)
		if port <= 0 {
			return nil
		}
		portByMacIdx[macIdx] = port
		macIndices = append(macIndices, macIdx)
		return nil
	})
	if walkErr != nil || len(macIndices) == 0 {
		snmp.Conn.Close()
		return nil, nil // not a VLAN-aware bridge, or no FDB — no topology data
	}

	// Resolve port names via IF-MIB (bridge port → ifIndex → ifName).
	// This is best-effort: if it fails, we fall back to numeric port numbers.
	portNames := ResolvePortNames(snmp, p.logger)

	// Build the evidence: one "neighbor" per unique MAC, carrying the MAC + local port.
	// The same MAC may appear on multiple VLANs; we emit ONE evidence per MAC.
	var evidence []scannerv2.Evidence
	seenMACs := make(map[string]bool)
	for _, macIdx := range macIndices {
		mac := macIndexToMAC(macIdx)
		if mac == "" {
			continue
		}
		// Deduplicate: same MAC may appear on multiple VLANs
		if seenMACs[mac] {
			continue
		}
		seenMACs[mac] = true

		port := portByMacIdx[macIdx]
		// Use human-readable port name if available, else fall back to numeric.
		localPort := strconv.Itoa(port)
		if name, ok := portNames[port]; ok && name != "" {
			localPort = name
		}
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:q_bridge_mib",
			Kind:       "neighbor",
			IP:         ip,
			Confidence: 0.75,
			ObservedAt: time.Now().UTC(),
			RawData: map[string]string{
				"neighbor_mac": mac,
				"protocol":     "Q-BRIDGE-MIB",
				"local_port":   localPort,
			},
		})
	}
	snmp.Conn.Close()
	return evidence, nil
}

// extractMACFromVLANIndex extracts the MAC portion (last 6 octets) from a
// Q-BRIDGE-MIB OID index of the form "<VLAN>.<MAC-octets>".
// The VLAN prefix can be 1 or 2 octets, so we skip everything before the last 6 integers.
// E.g. "1.170.187.204.221.238.255" → "170.187.204.221.238.255"
// E.g. "100.10.0.1.2.3.4.5" → "10.0.1.2.3.4.5" (VLAN=100 is 1 octet)
// E.g. "4096.10.0.1.2.3.4.5" → "10.0.1.2.3.4.5" (VLAN=4096 is 2 octets)
func extractMACFromVLANIndex(fullIndex string) string {
	parts := strings.Split(fullIndex, ".")
	if len(parts) < 7 {
		return "" // Need at least 1 VLAN octet + 6 MAC octets
	}
	// VLAN can be 1 or 2 octets; the last 6 elements are always the MAC.
	macParts := parts[len(parts)-6:]
	return strings.Join(macParts, ".")
}
