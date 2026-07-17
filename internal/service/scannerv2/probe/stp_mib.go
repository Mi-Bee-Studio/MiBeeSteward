// STPMIBProbe walks the BRIDGE-MIB dot1dStp subtree (STP information) to recover
// Spanning Tree Protocol topology facts: which bridge is the STP root, the
// designated root port, and each port's STP role/state (forwarding/blocking).
// This is topology metadata rather than direct adjacency — it explains why a
// physical link may carry no traffic (blocked by STP) and identifies the
// network's logical root. Evidence is emitted with protocol "STP" for the
// orchestrator; consumers can use root/designated roles to orient the topology
// view (root at the top) and port states to flag disabled edges.
package probe

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// STP-MIB OIDs (RFC 4318 / IEEE 802.1D):
//
//   - dot1dBaseBridgeAddress (1.3.6.1.2.1.17.1.1.0): scalar — the bridge's own MAC address.
//   - dot1dStpPortDesignatedBridge (1.3.6.1.2.1.17.2.2.1.15): OCTET STRING (8 bytes) per
//     bridge port. First 2 bytes = bridge priority (big-endian uint16), next 6 bytes = bridge
//     MAC. The OID index is the bridge port number (1-based integer).
const (
	oidDot1dBaseBridgeAddress       = "1.3.6.1.2.1.17.1.1.0"
	oidDot1dStpPortDesignatedBridge = "1.3.6.1.2.1.17.2.2.1.15"
)

// STPMIBProbe walks the STP-MIB dot1dStpPortTable on bridges/switches that speak
// SNMP. It discovers the designated bridge for each port — the bridge that is
// the STP root for that segment.
//
// Output: one "neighbor" Evidence per unique designated bridge, carrying the
// neighbor's MAC (the merge key) + the local bridge port. Only emits for ports
// whose designated bridge differs from the local bridge's own MAC (self-loops
// are skipped).
//
// Confidence: 0.7 — STP topology is indirect inference (the designated bridge
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

// Probe walks dot1dStpPortDesignatedBridge on ip:161. hint.Community/hint.Timeout apply.
func (p *STPMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
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

	// Get local bridge MAC (dot1dBaseBridgeAddress.0, scalar OCTET STRING).
	bridgeResult, err := snmp.Get([]string{oidDot1dBaseBridgeAddress})
	if err != nil || len(bridgeResult.Variables) == 0 {
		snmp.Conn.Close()
		return nil, nil
	}
	bridgeAddrBytes, ok := bridgeResult.Variables[0].Value.([]byte)
	if !ok || len(bridgeAddrBytes) != 6 {
		snmp.Conn.Close()
		return nil, nil
	}
	localBridgeMAC := formatMAC(bridgeAddrBytes)

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
	if walkErr != nil || len(entries) == 0 {
		snmp.Conn.Close()
		return nil, nil // no STP neighbors or STP-MIB unsupported
	}

	// Resolve port names via IF-MIB (bridge port → ifIndex → ifName).
	// This is best-effort: if it fails, we fall back to numeric port numbers.
	portNames := ResolvePortNames(snmp, p.logger)

	// Build the evidence: one "neighbor" per unique designated bridge MAC.
	var evidence []scannerv2.Evidence
	for _, entry := range entries {
		localPort := strconv.Itoa(entry.port)
		if name, ok := portNames[entry.port]; ok && name != "" {
			localPort = name
		}
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:stp_mib",
			Kind:       "neighbor",
			IP:         ip,
			Confidence: 0.7,
			ObservedAt: time.Now().UTC(),
			RawData: map[string]string{
				"neighbor_mac": entry.designatedMAC,
				"protocol":     "STP",
				"local_port":   localPort,
			},
		})
	}
	snmp.Conn.Close()
	return evidence, nil
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
