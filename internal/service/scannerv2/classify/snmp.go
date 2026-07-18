// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package classify

import (
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// SNMPClassifier turns SNMP evidence (sysObject group) into a host-level
// "snmp" service identity plus inferred device type/brand in metadata.
// Device type comes from sysServices bitmask + sysDescr patterns; brand from
// sysDescr keywords and the enterprise OID prefix in sysObjectID.
//
// Unlike port-based classifiers this identity has Port=161 and informs the
// host's overall type (router/switch/server/...).
type SNMPClassifier struct{}

func (SNMPClassifier) Service() string { return "snmp" }

func (SNMPClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	if len(ev) == 0 {
		return nil
	}
	idx := indexEvidence(ev)
	if len(idx.snmp) == 0 {
		return nil
	}
	// Merge varbinds across all snmp evidence (usually one).
	raw := map[string]string{}
	for _, e := range idx.snmp {
		for k, v := range e.RawData {
			raw[k] = v
		}
	}
	descr := raw["sys_descr"]
	services := raw["sys_services"]
	objID := raw["sys_object_id"]
	ifNum := raw["if_number"]

	md := map[string]string{
		"sys_descr":     descr,
		"sys_object_id": objID,
	}
	if t := inferTypeFromSNMP(services, descr, objID, ifNum); t != "" {
		md["inferred_type"] = t
	}
	if brand := inferBrand(descr, objID); brand != "" {
		md["inferred_brand"] = brand
	}
	// sysDescr almost always embeds the OS/product string (e.g. "Linux 5.15...",
	// "RouterOS 7.x", "Windows 10"). typeFromSysDescr already matches these
	// keywords to drive the type verdict, but without parsing them into an os
	// field the scan_os column stayed empty for the vast majority of devices
	// (os otherwise only comes from node_exporter/SSDP/NetBIOS, which rarely
	// apply). Mirror that matching into an os value so SNMP-reachable devices
	// get a populated OS regardless of subtype.
	if os := osFromSysDescr(strings.ToLower(descr)); os != "" {
		md["os_type"] = os
	}

	return []scannerv2.ServiceIdentity{{
		Service:    "snmp",
		Port:       161,
		Protocol:   "udp",
		Confidence: fuseConfidence(idx.snmp[0].Confidence, 0.95),
		Evidence:   append([]scannerv2.Evidence(nil), idx.snmp...),
		Metadata:   md,
	}}
}

// inferTypeFromSNMP maps the sysObject group to a device type. It combines four
// signals, strongest first:
//  1. sysObjectID enterprise prefix → exact type for well-known vendor OIDs
//     (the most reliable signal — vendor OIDs encode device class).
//  2. sysDescr keyword patterns → type for known OS/product strings.
//  3. sysServices BITS (RFC 1213: bit1=L2, bit2=L3, bit3=L4(end-to-end),
//     bit4=TCP, bit5=app) via bitmask tests, not exact decimal equality.
//  4. ifNumber — many interfaces reinforce switch/router.
//
// The previous version matched sysServices by exact decimal (==78/76/6), which
// missed the wide real-world variation (vendors report 72/74/78/200+ for
// switches) and ignored sysObjectID entirely, so most network devices fell
// through to "" → "other".
func inferTypeFromSNMP(servicesStr, descr, objID, ifNumberStr string) string {
	lower := strings.ToLower(descr)

	// 1. sysObjectID → type (strongest, vendor-specific).
	if t := typeFromOID(objID); t != "" {
		return t
	}

	// 2. sysDescr keyword patterns.
	if t := typeFromSysDescr(lower); t != "" {
		return t
	}

	// 3. sysServices bitmask + ifNumber heuristic.
	sv := atoiSafe(servicesStr)
	hasL2 := sv&1 != 0 // datalink (bridge)
	hasL3 := sv&2 != 0 // internet (IP forwarding)
	ifNum := atoiSafe(ifNumberStr)

	switch {
	case hasL3 && !hasL2 && ifNum <= 2:
		// Pure L3 forwarder with few interfaces — router/firewall. sysDescr
		// didn't match a known firewall product above, so default router.
		return "router"
	case hasL2 && hasL3 && ifNum > 4:
		// L2+L3 with many interfaces — a switch (managed L2/L3 switch).
		return "switch"
	case hasL2 && hasL3:
		// L2+L3 with few interfaces — could be a router/L3 switch; lean router.
		return "router"
	case hasL2 && !hasL3 && ifNum > 4:
		// Pure L2 with many ports — an unmanaged/layer-2 switch.
		return "switch"
	case sv >= 72:
		// High sysServices (many bits set incl. application) — a host/server.
		return "server"
	}

	return ""
}

// typeFromOID maps a sysObjectID enterprise prefix to a device type. Vendor OIDs
// encode device class far more reliably than sysServices — e.g. Cisco routers
// live under 9.1.1, Catalyst switches under 9.1.300+, HP ProCurve under
// 11.2.3.7.11. Returns "" for unknown/generic OIDs (e.g. Net-SNMP 8072).
func typeFromOID(objID string) string {
	if objID == "" {
		return ""
	}
	for _, e := range enterpriseOIDPrefix {
		if strings.HasPrefix(objID, e.prefix) {
			return e.typ
		}
	}
	return ""
}

// typeFromSysDescr matches known OS/product strings in sysDescr to a type.
// Covers the common network-OS and NAS/appliance descriptors that the old
// minimal set (firewall/nas/synology/qnap/linux/windows) missed.
func typeFromSysDescr(lower string) string {
	switch {
	// Firewalls / security appliances.
	case containsAny(lower, "fortigate", "palo alto", "checkpoint", "sonicwall",
		"pfsense", "opnsense", "juniper-srx", "cisco asa", "srx", "watchguard"):
		return "firewall"
	// NAS appliances.
	case containsAny(lower, "synology", "diskstation", "dsm ", "qnap",
		"readynas", "teramaster", "asustor", "thecus"):
		return "nas"
	// Wireless routers / APs with router OS.
	case containsAny(lower, "routeros", "mikrotik", "routeros rb", "openwrt",
		"padavan", "asuswrt", "tomato", "edgeos", "edgemax", "ubnt", "unifi"):
		return "router"
	// Switches (managed).
	case containsAny(lower, "procurve", "cisco ios", "catos", "comware",
		"h3c ", "vrp", "arubaos", "junos", "alliedware"):
		return "switch"
	// Generic routers.
	case containsAny(lower, "router", "cisco ios xr"):
		return "router"
	case containsAny(lower, "switch"):
		return "switch"
	// Cameras.
	case containsAny(lower, "hikvision", "dahua", "ip camera"):
		return "camera"
	// Generic hosts.
	case containsAny(lower, "linux", "windows", "freebsd", "vmware", "xen"):
		return "server"
	}
	return ""
}

// osFromSysDescr extracts a normalized OS family string from the sysDescr text.
// It reuses the same keyword families as typeFromSysDescr but returns an OS
// label ("linux"/"windows"/"routeros"/...) rather than a device type, because
// the OS is orthogonal to type (a Linux box could be a server, a camera, or a
// router). The result feeds scan_attributes.os so SNMP-reachable devices get a
// populated OS even when no node_exporter/SSDP/NetBIOS signal exists.
func osFromSysDescr(lower string) string {
	switch {
	case containsAny(lower, "routeros", "mikrotik"):
		return "RouterOS"
	case containsAny(lower, "openwrt"):
		return "OpenWrt"
	case containsAny(lower, "padavan", "asuswrt"):
		return "Linux"
	case containsAny(lower, "pfsense", "opnsense"):
		return "pfSense/OPNsense"
	case containsAny(lower, "synology", "dsm ", "diskstation"):
		return "DSM"
	case containsAny(lower, "qnap", "qts"):
		return "QTS"
	case containsAny(lower, "vmware", "esxi"):
		return "VMware ESXi"
	case containsAny(lower, "windows"):
		return "Windows"
	case containsAny(lower, "freebsd"):
		return "FreeBSD"
	case containsAny(lower, "darwin", "macos", "mac os"):
		return "macOS"
	case containsAny(lower, "linux"):
		return "Linux"
	case containsAny(lower, "android"):
		return "Android"
	}
	return ""
}

// containsAny reports whether s contains any of subs. Avoids repeating
// strings.Contains calls for the long keyword lists above.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// inferBrand extracts a vendor name from sysDescr keywords or the enterprise
// OID prefix in sysObjectID.
func inferBrand(descr, objID string) string {
	known := []string{
		// General IT
		"Cisco", "Juniper", "HP", "Dell", "Aruba", "Mikrotik", "Ubiquiti",
		"Fortinet", "Palo Alto", "Synology", "QNAP", "Arista", "Huawei",
		// Printer/storage
		"EPSON", "Canon", "Brother",
		// Camera
		"Hikvision", "Dahua", "Axis", "Bosch", "Sony", "Hanwha", "Vivotek",
		"Reolink", "Uniview", "Honeywell", "FLIR",
	}
	lower := strings.ToLower(descr)
	for _, b := range known {
		if strings.Contains(lower, strings.ToLower(b)) {
			return b
		}
	}
	// Enterprise OID prefix lookup.
	return brandFromOID(objID)
}

// enterpriseOIDPrefix maps the enterprise OID (1.3.6.1.4.1.<ent>) to a brand
// AND a device type. The type is the strongest signal inferTypeFromSNMP has —
// vendor OIDs encode device class (Cisco routers under 9.1., Catalyst switches
// under 9.1.300+, etc.). `typ` may be empty when the OID alone can't tell
// (e.g. Net-SNMP 8072 runs on anything); those fall through to sysDescr/sysServices.
var enterpriseOIDPrefix = []struct {
	prefix string
	brand  string
	typ    string
}{
	// Cisco: 9.1.x are routers/L3, 9.1.300+/9.1.5xxx+ are Catalyst/Nexus switches.
	// Coarse split: 9.1. → router, 9.1.3/9.1.5/9.1.7/9.1.9 (300-999 & 5000+) → switch.
	{"1.3.6.1.4.1.9.1.300.", "Cisco", "switch"},
	{"1.3.6.1.4.1.9.1.5", "Cisco", "switch"}, // 5xx Catalyst
	{"1.3.6.1.4.1.9.1.7", "Cisco", "switch"}, // 7xx Catalyst
	{"1.3.6.1.4.1.9.1.9", "Cisco", "switch"}, // 9xx Nexus
	{"1.3.6.1.4.1.9.1.", "Cisco", "router"},  // default Cisco = router
	{"1.3.6.1.4.1.9.", "Cisco", "router"},
	// HP: 11.2.3.7.11.x = ProCurve/Aruba switches; 11.2.3.2 = ProLiant servers.
	{"1.3.6.1.4.1.11.2.3.7.11.", "HP", "switch"},
	{"1.3.6.1.4.1.11.2.3.2.", "HP", "server"},
	{"1.3.6.1.4.1.11.", "HP", ""},
	{"1.3.6.1.4.1.674.10892.", "Dell", "server"}, // Dell iDRAC/PowerEdge
	{"1.3.6.1.4.1.674.", "Dell", ""},
	// Huawei: 2011.2.22 = routers/switches (VRP). Lean router without finer split.
	{"1.3.6.1.4.1.2011.2.22.", "Huawei", "router"},
	{"1.3.6.1.4.1.2011.", "Huawei", ""},
	{"1.3.6.1.4.1.2636.", "Juniper", "router"}, // JUNOS = router/L3
	{"1.3.6.1.4.1.14823.", "Aruba", "switch"},  // Aruba = switches/APs
	{"1.3.6.1.4.1.30065.", "Mikrotik", "router"},
	{"1.3.6.1.4.1.8072.", "NetSNMP", ""}, // generic — host runs net-snmp, type unknown here
	{"1.3.6.1.4.1.39165.", "Hikvision", "camera"},
	{"1.3.6.1.4.1.100484.", "Dahua", "camera"},
	{"1.3.6.1.4.1.368.", "Axis", "camera"},
	{"1.3.6.1.4.1.12325.", "Synology", "nas"},
	{"1.3.6.1.4.1.24681.", "QNAP", "nas"},
	// Ubiquiti: 41112 UniFi/EdgeSwitch.
	{"1.3.6.1.4.1.41112.", "Ubiquiti", "router"},
	// H3C/Comware.
	{"1.3.6.1.4.1.25506.", "H3C", "switch"},
	// TP-Link.
	{"1.3.6.1.4.1.11863.", "TP-Link", "router"},
	// Netgear routers/switches.
	{"1.3.6.1.4.1.4526.", "Netgear", "router"},
	// F5 BIG-IP load balancers (often act as firewall/gateway).
	{"1.3.6.1.4.1.3375.", "F5", "firewall"},
}

func brandFromOID(objID string) string {
	if objID == "" {
		return ""
	}
	for _, e := range enterpriseOIDPrefix {
		if strings.HasPrefix(objID, e.prefix) {
			return e.brand
		}
	}
	return ""
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			// multi-token: stop at first non-digit
			if n != 0 {
				return n
			}
			continue
		}
		n = n*10 + int(r-'0')
	}
	return n
}
