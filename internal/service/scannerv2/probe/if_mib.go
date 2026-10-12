// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// IFMIBProbe walks the device's own interface census (#529): ifTable
// (ifDescr/ifType/ifSpeed/ifPhysAddress) + ifXTable (ifName) joined with
// ipAddrTable (the IPv4 answered on each port). One "interface"-kind evidence
// row per port; the orchestrator upserts them into device_interfaces. The
// per-interface IP is the multi-homed gold - which address lives on which
// port is exactly what a single devices.ip_address row can never express.
//
// Name: "active:if_mib".
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

// IF-MIB / ipAddrTable OIDs:
//
//   - ifDescr (1.3.6.1.2.1.2.2.1.2): per-ifIndex interface description.
//   - ifSpeed (1.3.6.1.2.1.2.2.1.5): bits/s (32-bit; WAN-scale speeds need
//     ifHighSpeed, which home LAN gear rarely populates differently).
//   - ifPhysAddress (1.3.6.1.2.1.2.2.1.6): the port's MAC.
//   - ifName (1.3.6.1.2.1.31.1.1.1.1): ifXTable's human-friendly name.
//   - ipAdEntIfIndex (1.3.6.1.2.1.4.20.1.2): ipAddrTable's IP -> ifIndex.
const (
	oidIfDescr    = "1.3.6.1.2.1.2.2.1.2"
	oidIfSpeed    = "1.3.6.1.2.1.2.2.1.5"
	oidIfPhysAddr = "1.3.6.1.2.1.2.2.1.6"
	oidIfNameX    = "1.3.6.1.2.1.31.1.1.1.1"
	oidIPAdEntIdx = "1.3.6.1.2.1.4.20.1.2"
)

// IFMIBProbe collects the interface census from IF-MIB + ipAddrTable.
type IFMIBProbe struct {
	logger *slog.Logger
}

// NewIFMIBProbe returns an IF-MIB probe. logger may be nil.
func NewIFMIBProbe(logger *slog.Logger) *IFMIBProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &IFMIBProbe{logger: logger}
}

func (p *IFMIBProbe) Name() string { return "active:if_mib" }

// Probe walks the interface tables on ip:161. hint.Community/hint.Timeout
// apply; a bound v3 credential routes through SNMPv3.
func (p *IFMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	snmp, err := connectSNMPWithRetries(ip, hint, gosnmp.Version2c, 1)
	if err != nil {
		return nil, nil // unreachable: not an error, just no census
	}

	names := make(map[int]string)    // ifIndex -> ifName (ifXTable preferred)
	descrs := make(map[int]string)   // ifIndex -> ifDescr
	macs := make(map[int]string)     // ifIndex -> MAC
	speeds := make(map[int]int64)    // ifIndex -> Mbps
	ipByIf := make(map[int][]string) // ifIndex -> IPv4 list (ipAddrTable)

	_ = snmp.Walk(oidIfNameX, func(pdu gosnmp.SnmpPDU) error {
		if idx := walkIndex(pdu.Name, oidIfNameX); idx > 0 {
			if s, ok := octetStringValue(pdu); ok {
				names[idx] = s
			}
		}
		return nil
	})
	_ = snmp.Walk(oidIfDescr, func(pdu gosnmp.SnmpPDU) error {
		if idx := walkIndex(pdu.Name, oidIfDescr); idx > 0 {
			if s, ok := octetStringValue(pdu); ok {
				descrs[idx] = s
			}
		}
		return nil
	})
	_ = snmp.Walk(oidIfPhysAddr, func(pdu gosnmp.SnmpPDU) error {
		if idx := walkIndex(pdu.Name, oidIfPhysAddr); idx > 0 {
			if b, ok := pdu.Value.([]byte); ok && len(b) == 6 {
				macs[idx] = formatMAC(b)
			}
		}
		return nil
	})
	_ = snmp.Walk(oidIfSpeed, func(pdu gosnmp.SnmpPDU) error {
		if idx := walkIndex(pdu.Name, oidIfSpeed); idx > 0 {
			if v, ok := gosnmpToIntValue(pdu.Value); ok {
				speeds[idx] = int64(v) / 1_000_000
			}
		}
		return nil
	})
	// ipAddrTable is keyed by the IP itself (ipAdEntIfIndex.IP -> ifIndex).
	_ = snmp.Walk(oidIPAdEntIdx, func(pdu gosnmp.SnmpPDU) error {
		suffix := indexSuffix(pdu.Name, oidIPAdEntIdx)
		if suffix == "" {
			return nil
		}
		// The index is the IPv4 as dotted octets ("192.168.1.1" style for v4).
		parts := strings.Split(suffix, ".")
		if len(parts) != 4 {
			return nil
		}
		ipStr := strings.Join(parts, ".")
		if v, ok := gosnmpToIntValue(pdu.Value); ok {
			ipByIf[v] = append(ipByIf[v], ipStr)
		}
		return nil
	})
	snmp.Close()

	if len(names) == 0 && len(descrs) == 0 {
		return nil, nil // no IF-MIB data
	}

	indices := make(map[int]bool, len(descrs))
	for idx := range descrs {
		indices[idx] = true
	}
	for idx := range names {
		indices[idx] = true
	}

	var evidence []scannerv2.Evidence
	for idx := range indices {
		mac := macs[idx]
		ips := ipByIf[idx]
		if mac == "" && len(ips) == 0 {
			continue // virtual/empty port with neither identity
		}
		name := names[idx]
		if name == "" {
			name = descrs[idx]
		}
		ipStr := ""
		if len(ips) > 0 {
			ipStr = ips[0]
		}
		rd := map[string]string{
			"if_index": strconv.Itoa(idx),
			"if_name":  name,
			"if_descr": descrs[idx],
			"mac":      mac,
			"ip":       ipStr,
		}
		if len(ips) > 1 {
			rd["ip_aliases"] = strings.Join(ips[1:], ",")
		}
		if sp := speeds[idx]; sp > 0 {
			rd["speed_mbps"] = strconv.FormatInt(sp, 10)
		}
		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:if_mib",
			Kind:       "interface",
			IP:         ip,
			Protocol:   "snmp",
			Confidence: 0.9,
			ObservedAt: time.Now().UTC(),
			RawData:    rd,
		})
	}
	return evidence, nil
}

// walkIndex extracts the numeric trailing index from a walked OID
// (".1.3.6.1.2.1.31.1.1.1.1.7" -> 7). Returns 0 when the suffix isn't a plain
// integer (some tables have composite indices; those rows are skipped).
func walkIndex(name, prefix string) int {
	return gosnmpToInt(indexSuffix(name, prefix))
}

// octetStringValue renders an SNMP OCTET STRING PDU as text: gosnmp delivers
// wire-decoded octet strings as []byte, but scripted tests (and some agents)
// hand over a plain string - accept both shapes.
func octetStringValue(pdu gosnmp.SnmpPDU) (string, bool) {
	switch v := pdu.Value.(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	default:
		return "", false
	}
}
