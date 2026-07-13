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

// Bridge-MIB OID subtrees (RFC 4188 / 1493):
//
//   - dot1dBasePortTable (1.3.6.1.2.1.17.1.4): port-number → ifIndex mapping.
//     Indexed by dot1dBasePort (a small integer). Gives us local_port.
//   - dot1dTpFdbTable (1.3.6.1.2.1.17.4.3.1): the forwarding database — which
//     MACs are seen on which bridge port. Indexed by MAC + port.
//     1.3.6.1.2.1.17.4.3.1.1 = dot1dTpFdbAddress (the MAC)
//     1.3.6.1.2.1.17.4.3.1.2 = dot1dTpFdbPort (the bridge port number)
//
// By walking dot1dTpFdbAddress we get every learned MAC; its sibling
// dot1dTpFdbPort tells us which bridge port that MAC lives behind. Combined
// with dot1dBasePortIfIndex we can name the local interface.
const (
	oidDot1dTpFdbAddress    = "1.3.6.1.2.1.17.4.3.1.1" // MAC address (octet string)
	oidDot1dTpFdbPort       = "1.3.6.1.2.1.17.4.3.1.2" // bridge port number (int)
	oidDot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2" // port → ifIndex
)

// BridgeMIBProbe walks the Bridge-MIB forwarding database (dot1dTpFdbTable) on
// switches/bridges that speak SNMP. It discovers which MAC addresses are visible
// behind each port — the L2 adjacency that topology views render as "device A
// connects to switch B on port X".
//
// Output: one "neighbor" Evidence per learned MAC, carrying the neighbor's MAC
// (the merge key) + the local bridge port. The orchestrator's neighbor-extract
// step turns these into device_neighbors rows via RecordNeighbors.
//
// Only devices acting as bridges/switches have a populated FDB; endpoints
// (cameras, servers) return nothing and the probe is a no-op for them.
//
// Name: "active:bridge_mib".
type BridgeMIBProbe struct {
	logger *slog.Logger
}

// NewBridgeMIBProbe returns a Bridge-MIB probe. logger may be nil.
func NewBridgeMIBProbe(logger *slog.Logger) *BridgeMIBProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &BridgeMIBProbe{logger: logger}
}

func (p *BridgeMIBProbe) Name() string { return "active:bridge_mib" }

// Probe walks dot1dTpFdbTable on ip:161. hint.Community/hint.Timeout apply.
func (p *BridgeMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
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
	defer snmp.Conn.Close()

	// Walk the FDB: collect {MAC-octet-index → port-number}.
	// The OID index for dot1dTpFdbTable is the MAC itself (6 octet subidentifiers),
	// so pdu.Name ends in the MAC as dotted decimal (e.g. ...1.170.187.204.221.238.255).
	portByMacIdx := map[string]int{}
	var macIndices []string

	walkErr := snmp.Walk(oidDot1dTpFdbPort, func(pdu gosnmp.SnmpPDU) error {
		// pdu.Name = full OID including the MAC index suffix.
		// pdu.Value = the bridge port number (integer).
		macIdx := indexSuffix(pdu.Name, oidDot1dTpFdbPort)
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
		return nil, nil // not a bridge, or no FDB — no topology data
	}

	// Build the evidence: one "neighbor" per MAC, carrying the MAC + local port.
	var evidence []scannerv2.Evidence
	for _, macIdx := range macIndices {
		mac := macIndexToMAC(macIdx)
		if mac == "" {
			continue
		}
		port := portByMacIdx[macIdx]
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:bridge_mib",
			Kind:       "neighbor",
			IP:         ip,
			Confidence: 0.8,
			ObservedAt: time.Now().UTC(),
			RawData: map[string]string{
				"neighbor_mac": mac,
				"protocol":     "Bridge-MIB",
				"local_port":   strconv.Itoa(port),
			},
		})
	}
	return evidence, nil
}

// indexSuffix extracts the OID index suffix (everything after the prefix) from a
// full OID returned by gosnmp. E.g. ".1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255"
// with prefix "1.3.6.1.2.1.17.4.3.1.2" → "170.187.204.221.238.255".
func indexSuffix(fullOID, prefix string) string {
	f := strings.TrimPrefix(fullOID, ".")
	p := strings.TrimPrefix(prefix, ".")
	tail := strings.TrimPrefix(f, p)
	if tail == f {
		return ""
	}
	return strings.TrimPrefix(tail, ".")
}

// macIndexToMAC converts a MAC-as-OID-index suffix ("170.187.204.221.238.255")
// to canonical "aa:bb:cc:dd:ee:ff". Returns "" if the suffix isn't 6 octets.
func macIndexToMAC(suffix string) string {
	parts := strings.Split(suffix, ".")
	if len(parts) != 6 {
		return ""
	}
	var octets [6]byte
	for i, s := range parts {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 || v > 255 {
			return ""
		}
		octets[i] = byte(v)
	}
	return formatMAC(octets[:])
}

// gosnmpToInt extracts an int from a gosnmp varbind value (the value type for
// dot1dTpFdbPort is Integer).
func gosnmpToInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint:
		return int(n)
	case uint64:
		return int(n)
	default:
		return 0
	}
}
