package probe

import (
	"log/slog"

	"github.com/gosnmp/gosnmp"
)

// ifName (1.3.6.1.2.1.31.1.1.1.1): ifIndex → human-readable interface name
//
// By walking dot1dBasePortIfIndex we get the mapping from bridge port numbers
// to ifIndex values. Then walking ifName gives us the human-readable names
// (e.g. "ge-0/0/3", "GigabitEthernet0/0/3").

// oidIfName is the IF-MIB ifName OID (1.3.6.1.2.1.31.1.1.1.1): ifIndex → interface name.
// Note: oidDot1dBasePortIfIndex is defined in bridge_mib.go and reused here.
const oidIfName = "1.3.6.1.2.1.31.1.1.1.1"

// ResolvePortNames walks the Bridge-MIB dot1dBasePortIfIndex table and IF-MIB
// ifName table to resolve bridge port numbers to human-readable interface names.
// It returns a map[bridgePortNumber]string where the value is the ifName (e.g.
// "ge-0/0/3"). On any SNMP error, it returns an empty map (caller should fall
// back to numeric port numbers).
//
// The gosnmp connection must already be established by the caller; this function
// does not connect or close the connection.
func ResolvePortNames(snmp *gosnmp.GoSNMP, logger *slog.Logger) map[int]string {
	if snmp == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Walk dot1dBasePortIfIndex: bridge port number → ifIndex
	// The OID index is the bridge port number (extracted from pdu.Name suffix).
	// pdu.Value is the ifIndex.
	portToIfIndex := map[int]int{}
	walkErr := snmp.Walk(oidDot1dBasePortIfIndex, func(pdu gosnmp.SnmpPDU) error {
		// Extract bridge port number from the OID index suffix
		portIdx := indexSuffix(pdu.Name, oidDot1dBasePortIfIndex)
		if portIdx == "" {
			return nil
		}
		port := gosnmpToInt(portIdx)
		if port <= 0 {
			return nil
		}
		ifIndex := gosnmpToInt(pdu.Value)
		if ifIndex > 0 {
			portToIfIndex[port] = ifIndex
		}
		return nil
	})
	if walkErr != nil {
		logger.Debug("failed to walk dot1dBasePortIfIndex", "err", walkErr)
		return nil
	}
	if len(portToIfIndex) == 0 {
		return nil
	}

	// Walk IF-MIB ifName: ifIndex → interface name
	// The OID index is the ifIndex (extracted from pdu.Name suffix).
	// pdu.Value is the interface name string.
	ifIndexToName := map[int]string{}
	walkErr = snmp.Walk(oidIfName, func(pdu gosnmp.SnmpPDU) error {
		// Extract ifIndex from the OID index suffix
		ifIdx := indexSuffix(pdu.Name, oidIfName)
		if ifIdx == "" {
			return nil
		}
		ifIndex := gosnmpToInt(ifIdx)
		if ifIndex <= 0 {
			return nil
		}
		if name, ok := pdu.Value.(string); ok && name != "" {
			ifIndexToName[ifIndex] = name
		}
		return nil
	})
	if walkErr != nil {
		logger.Debug("failed to walk ifName", "err", walkErr)
		return nil
	}
	if len(ifIndexToName) == 0 {
		return nil
	}

	// Build the final map: bridge port → ifName
	result := make(map[int]string)
	for port, ifIndex := range portToIfIndex {
		if name, ok := ifIndexToName[ifIndex]; ok {
			result[port] = name
		}
	}
	return result
}
