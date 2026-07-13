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

// LLDP-MIB OIDs (IEEE 802.1AB, OID prefix 1.0.8802.1.1.2.1.4.1 = lldpRemTable).
// The table is indexed by (lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex).
// lldpRemLocalPortNum is the local port on the surveyed device — directly
// analogous to bridge_mib's local_port.
//
//	lldpRemChassisIdSubtype ...1.4.1.1.4   (int: 4=MAC addr, 7=locally assigned, ...)
//	lldpRemChassisId        ...1.4.1.1.5   (octet string: the chassis id payload)
//	lldpRemPortIdSubtype    ...1.4.1.1.6
//	lldpRemPortId           ...1.4.1.1.7   (the remote port identifier)
//	lldpRemPortDesc         ...1.4.1.1.8   (human-readable remote port, e.g. "ge-0/0/1")
//	lldpRemSysName          ...1.4.1.1.9   (remote system name)
const (
	oidLldpRemTable      = "1.0.8802.1.1.2.1.4.1"
	oidLldpRemChassisId  = "1.0.8802.1.1.2.1.4.1.1.5" // chassis id payload (octet string)
	oidLldpRemChassisSub = "1.0.8802.1.1.2.1.4.1.1.4" // chassis id subtype (int)
	oidLldpRemPortId     = "1.0.8802.1.1.2.1.4.1.1.7" // remote port id (octet string)
	oidLldpRemPortDesc   = "1.0.8802.1.1.2.1.4.1.1.8" // remote port description (string)
)

// LLDPMIBProbe walks the LLDP-MIB lldpRemTable on switches/APs that speak SNMP
// and run LLDP. It discovers LLDP-advertised neighbors — the L2 adjacency that
// the topology view renders. LLDP is the cross-vendor standard (vs CDP, which is
// Cisco-proprietary), so this probe sees neighbors from any LLDP-speaking peer.
//
// Output: one "neighbor" Evidence per remote chassis, carrying the neighbor's
// MAC (subtype-4 chassis id, the merge key), the local LLDP port number, and the
// remote port id/description. The orchestrator's neighbor-extract step turns
// these into device_neighbors rows via RecordNeighbors — identical to Bridge-MIB.
//
// Only LLDP-capable devices (managed switches, APs, some NAS/IP phones) populate
// lldpRemTable; endpoints without LLDP return nothing and the probe is a no-op.
//
// This complements Bridge-MIB: Bridge-MIB sees every learned MAC behind a port
// (broadcast-domain), LLDP sees only LLDP-speaking peers (a sparser but richer
// adjacency — each carries the peer's identity, not just a MAC).
//
// Name: "active:lldp_mib". Privileges: none (UDP/161, like all SNMP probes).
type LLDPMIBProbe struct {
	logger *slog.Logger
}

// NewLLDPMIBProbe returns an LLDP-MIB probe. logger may be nil.
func NewLLDPMIBProbe(logger *slog.Logger) *LLDPMIBProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &LLDPMIBProbe{logger: logger}
}

func (p *LLDPMIBProbe) Name() string { return "active:lldp_mib" }

// Probe walks lldpRemTable on ip:161. hint.Community/hint.Timeout apply.
func (p *LLDPMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
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

	// Walk three columns of lldpRemTable, keyed by the index suffix. The index
	// is "<timeMark>.<localPort>.<remIndex>" — localPort (2nd sub-identifier) is
	// the surveyed device's port facing the neighbor. lldpRemChassisId is the
	// densest column (one row per remote system); its presence drives the loop.
	subByIndex := map[string]int{}
	if err := snmp.Walk(oidLldpRemChassisSub, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidLldpRemChassisSub); s != "" {
			subByIndex[s] = gosnmpToInt(pdu.Value)
		}
		return nil
	}); err != nil {
		return nil, nil // SNMP failed or LLDP-MIB unsupported — no topology data
	}
	payloadByIndex := map[string][]byte{}
	_ = snmp.Walk(oidLldpRemChassisId, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidLldpRemChassisId); s != "" {
			if b, ok := pdu.Value.([]byte); ok {
				payloadByIndex[s] = b
			}
		}
		return nil
	})
	portIDByIndex := map[string]string{}
	_ = snmp.Walk(oidLldpRemPortId, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidLldpRemPortId); s != "" {
			if b, ok := pdu.Value.([]byte); ok {
				portIDByIndex[s] = string(b)
			}
		}
		return nil
	})
	if len(payloadByIndex) == 0 {
		return nil, nil // no LLDP neighbors
	}

	// Build evidence: one "neighbor" per remote chassis with a subtype-4 MAC id.
	// Other chassis-id subtypes (7 = locally assigned, etc.) don't give a MAC
	// merge key against the devices table, so we skip them rather than emit
	// un-joinable edges.
	var evidence []scannerv2.Evidence
	for suffix, payload := range payloadByIndex {
		mac := lldpChassisToMAC(subByIndex[suffix], payload)
		if mac == "" {
			continue
		}
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:lldp_mib",
			Kind:       "neighbor",
			IP:         ip,
			Confidence: 0.85, // LLDP is explicit adjacency — slightly higher than Bridge-MIB's learned-MAC
			ObservedAt: time.Now().UTC(),
			RawData: map[string]string{
				"neighbor_mac": mac,
				"protocol":     "LLDP",
				"local_port":   lldpLocalPortFromIndex(suffix),
				"remote_port":  portIDByIndex[suffix],
			},
		})
	}
	return evidence, nil
}

// lldpLocalPortFromIndex extracts the lldpRemLocalPortNum (2nd sub-identifier)
// from a lldpRemTable index suffix "<timeMark>.<localPort>.<remIndex>".
func lldpLocalPortFromIndex(suffix string) string {
	parts := strings.Split(suffix, ".")
	if len(parts) < 3 {
		return ""
	}
	// parts[1] = localPortNum; return as-is (numeric string, like bridge_mib).
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return ""
	}
	return parts[1]
}

// lldpChassisToMAC interprets an LLDP chassis id by its subtype. Only subtype 4
// (MAC address, 6 octets) yields a canonical MAC merge key. Other subtypes
// return "" so the caller can skip non-MAC neighbors.
func lldpChassisToMAC(subtype int, payload []byte) string {
	if subtype != 4 || len(payload) != 6 {
		return ""
	}
	return formatMAC(payload)
}
