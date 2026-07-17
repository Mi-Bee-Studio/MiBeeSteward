// Package-level note: the CDP-MIB probe lives in package probe alongside the
// other scannerv2 active probes.
//
// CDPMIBProbe walks CISCO-CDP-MIB cdpCacheTable on Cisco (and CDP-speaking)
// switches to discover Cisco Discovery Protocol neighbors: device id (often the
// hostname), platform string, software version, and the remote port. Because
// CDP-MIB does not expose the neighbor's MAC, the device id is used as the
// neighbor merge key. The probe runs over UDP/161 (SNMP) and emits neighbor
// Evidence with protocol "CDP" for the orchestrator's L2-adjacency pipeline.
// It is the Cisco-proprietary counterpart to the cross-vendor LLDP-MIB probe.
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

// CISCO-CDP-MIB OID subtrees for cdpCacheTable (1.3.6.1.4.1.9.9.23.1.2.1.1):
//   - cdpCacheIfIndex (.1): the index (local interface ifIndex)
//   - cdpCacheDeviceId (.3): remote device identifier string (often hostname)
//   - cdpCacheAddress (.4): neighbor's management IP (octet string, type+length+NLPID+addrLen+addr)
//   - cdpCacheVersion (.6): remote software version string
//   - cdpCacheDevicePort (.7): remote port identifier string
//   - cdpCachePlatform (.8): remote platform string (e.g. "cisco WS-C2960S-24TS-L")
//
// The table is indexed by cdpCacheIfIndex (a single integer, the local interface ifIndex).
const (
	oidCDPDeviceID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.3" // cdpCacheDeviceId (string)
	oidCDPAddress    = "1.3.6.1.4.1.9.9.23.1.2.1.1.4" // cdpCacheAddress (octet string)
	oidCDPVersion    = "1.3.6.1.4.1.9.9.23.1.2.1.1.6" // cdpCacheVersion (string)
	oidCDPDevicePort = "1.3.6.1.4.1.9.9.23.1.2.1.1.7" // cdpCacheDevicePort (string)
	oidCDPPlatform   = "1.3.6.1.4.1.9.9.23.1.2.1.1.8" // cdpCachePlatform (string)
	oidIfNameCDP     = "1.3.6.1.2.1.31.1.1.1.1"       // IF-MIB ifName (for port name resolution)
)

// CDPMIBProbe walks CISCO-CDP-MIB cdpCacheTable on Cisco devices to discover
// L2 neighbors via CDP. It emits neighbor evidence with topology keys (neighbor_mac,
// protocol, local_port, remote_port) and identity keys (sys_name, platform, version,
// neighbor_ip).
//
// The CDP-MIB table is indexed by cdpCacheIfIndex (the local interface ifIndex). We
// walk five columns keyed by the same index suffix, then merge them into one evidence
// per unique ifIndex entry.
//
// CDP-MIB does NOT provide the neighbor's MAC address directly. We use cdpCacheDeviceId
// as the neighbor_mac merge key (per the task spec), even though it's not a MAC — this
// is acceptable because the orchestrator handles non-MAC values gracefully (they simply
// won't join to the devices table). The passive CDP frame listener (T5) provides
// MAC-based edges; CDP-MIB's value is the identity enrichment (platform, version, sys_name).
//
// Output: one "neighbor" Evidence per unique cdpCacheIfIndex entry, carrying:
//   - neighbor_mac: cdpCacheDeviceId (the merge key, though not a MAC)
//   - protocol: "CDP"
//   - local_port: ifName resolved from cdpCacheIfIndex (ifIndex → ifName walk)
//   - remote_port: cdpCacheDevicePort
//   - sys_name: cdpCacheDeviceId
//   - platform: cdpCachePlatform
//   - version: cdpCacheVersion
//   - neighbor_ip: extracted IPv4 from cdpCacheAddress (if present)
//
// Only Cisco devices with CDP enabled and SNMP accessible return data; others are a no-op.
//
// Name: "active:cdp_mib".
type CDPMIBProbe struct {
	logger *slog.Logger
}

// NewCDPMIBProbe returns a CDP-MIB probe. logger may be nil.
func NewCDPMIBProbe(logger *slog.Logger) *CDPMIBProbe {
	if logger == nil {
		logger = slog.Default()
	}
	return &CDPMIBProbe{logger: logger}
}

func (p *CDPMIBProbe) Name() string { return "active:cdp_mib" }

// Probe walks cdpCacheTable on ip:161. hint.Community/hint.Timeout apply.
func (p *CDPMIBProbe) Probe(_ context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
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

	// Walk five columns of cdpCacheTable, keyed by cdpCacheIfIndex (single integer).
	// cdpCacheDeviceId is the densest column; its presence drives the loop.
	deviceIDByIndex := map[string]string{}
	walkErr := snmp.Walk(oidCDPDeviceID, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidCDPDeviceID); s != "" {
			if v, ok := pdu.Value.(string); ok && v != "" {
				deviceIDByIndex[s] = v
			}
		}
		return nil
	})
	if walkErr != nil || len(deviceIDByIndex) == 0 {
		snmp.Conn.Close()
		return nil, nil // no CDP neighbors or CDP-MIB unsupported
	}

	addressByIndex := map[string][]byte{}
	_ = snmp.Walk(oidCDPAddress, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidCDPAddress); s != "" {
			if b, ok := pdu.Value.([]byte); ok && len(b) > 0 {
				addressByIndex[s] = b
			}
		}
		return nil
	})

	devicePortByIndex := map[string]string{}
	_ = snmp.Walk(oidCDPDevicePort, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidCDPDevicePort); s != "" {
			if v, ok := pdu.Value.(string); ok && v != "" {
				devicePortByIndex[s] = v
			}
		}
		return nil
	})

	platformByIndex := map[string]string{}
	_ = snmp.Walk(oidCDPPlatform, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidCDPPlatform); s != "" {
			if v, ok := pdu.Value.(string); ok && v != "" {
				platformByIndex[s] = v
			}
		}
		return nil
	})

	versionByIndex := map[string]string{}
	_ = snmp.Walk(oidCDPVersion, func(pdu gosnmp.SnmpPDU) error {
		if s := indexSuffix(pdu.Name, oidCDPVersion); s != "" {
			if v, ok := pdu.Value.(string); ok && v != "" {
				versionByIndex[s] = v
			}
		}
		return nil
	})

	// Resolve port names via IF-MIB (ifIndex → ifName).
	// The index in CDP-MIB IS an ifIndex, so we can walk ifName directly.
	// Collect the unique ifIndex values first.
	var ifIndices []int
	for suffix := range deviceIDByIndex {
		ifIdx := cdpIfIndexFromIndex(suffix)
		if ifIdx > 0 {
			ifIndices = append(ifIndices, ifIdx)
		}
	}
	ifNames := resolveIfNames(snmp, ifIndices, p.logger)

	// Build evidence: one "neighbor" per unique cdpCacheIfIndex entry.
	var evidence []scannerv2.Evidence
	for suffix, deviceID := range deviceIDByIndex {
		ifIdx := cdpIfIndexFromIndex(suffix)
		if ifIdx == 0 {
			continue
		}
		neighborIP := extractIPv4FromCDPAddress(addressByIndex[suffix])

		// Use human-readable port name if available, else fall back to numeric ifIndex.
		localPort := strconv.Itoa(ifIdx)
		if name, ok := ifNames[ifIdx]; ok && name != "" {
			localPort = name
		}

		evidence = append(evidence, scannerv2.Evidence{
			Source:     "active:cdp_mib",
			Kind:       "neighbor",
			IP:         ip,
			Confidence: 0.8, // CDP is explicit protocol discovery, Cisco-only but reliable
			ObservedAt: time.Now().UTC(),
			RawData: map[string]string{
				"neighbor_mac": deviceID, // Per plan: use Device ID as merge key (not a MAC)
				"protocol":     "CDP",
				"local_port":   localPort,
				"remote_port":  devicePortByIndex[suffix],
				"sys_name":     deviceID, // cdpCacheDeviceId serves as sys_name
				"platform":     platformByIndex[suffix],
				"version":      versionByIndex[suffix],
				"neighbor_ip":  neighborIP,
			},
		})
	}

	snmp.Conn.Close()
	return evidence, nil
}

// cdpIfIndexFromIndex extracts the cdpCacheIfIndex from a CDP-MIB index suffix.
// The index is a single integer (the local interface ifIndex).
func cdpIfIndexFromIndex(suffix string) int {
	parts := strings.Split(suffix, ".")
	if len(parts) != 1 {
		return 0
	}
	idx, err := strconv.Atoi(parts[0])
	if err != nil || idx <= 0 {
		return 0
	}
	return idx
}

// resolveIfNames walks IF-MIB ifName for specific ifIndex values.
// Returns a map[ifIndex]string where the value is the ifName (e.g. "GigabitEthernet0/1").
// On any SNMP error, it returns an empty map (caller should fall back to numeric ports).
func resolveIfNames(snmp *gosnmp.GoSNMP, ifIndices []int, logger *slog.Logger) map[int]string {
	if snmp == nil || len(ifIndices) == 0 {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Walk ifName and collect only the ifIndex values we care about.
	result := make(map[int]string)
	walkErr := snmp.Walk(oidIfNameCDP, func(pdu gosnmp.SnmpPDU) error {
		ifIdx := indexSuffix(pdu.Name, oidIfNameCDP)
		if ifIdx == "" {
			return nil
		}
		idx := gosnmpToInt(ifIdx)
		if idx <= 0 {
			return nil
		}
		// Only collect if it's one we're looking for
		for _, target := range ifIndices {
			if idx == target {
				if name, ok := pdu.Value.(string); ok && name != "" {
					result[idx] = name
				}
				break
			}
		}
		return nil
	})
	if walkErr != nil {
		logger.Debug("failed to walk ifName for CDP-MIB", "err", walkErr)
		return nil
	}
	return result
}

// extractIPv4FromCDPAddress extracts the IPv4 address from a cdpCacheAddress octet string.
// The format is: type(1) + length(1) + NLPID(1=0xcc for IPv4) + addrLen(1) + addr(4).
// Returns "" if the address is not IPv4 or malformed.
func extractIPv4FromCDPAddress(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// type = 1 (IPv4), NLPID = 0xcc for IPv4
	if data[0] != 1 || data[2] != 0xcc {
		return ""
	}
	addrLen := int(data[3])
	if addrLen != 4 || len(data) < 4+addrLen {
		return ""
	}
	ipBytes := data[4 : 4+addrLen]
	return formatIPv4(ipBytes)
}

// formatIPv4 converts 4 bytes to dotted-decimal notation (e.g. "192.168.1.1").
func formatIPv4(b []byte) string {
	if len(b) != 4 {
		return ""
	}
	return strconv.Itoa(int(b[0])) + "." +
		strconv.Itoa(int(b[1])) + "." +
		strconv.Itoa(int(b[2])) + "." +
		strconv.Itoa(int(b[3]))
}
