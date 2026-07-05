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

	md := map[string]string{
		"sys_descr":     descr,
		"sys_object_id": objID,
	}
	if t := inferTypeFromSNMP(services, descr); t != "" {
		md["inferred_type"] = t
	}
	if brand := inferBrand(descr, objID); brand != "" {
		md["inferred_brand"] = brand
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

// inferTypeFromSNMP maps sysServices bitmask + sysDescr patterns to a device
// type. sysServices is a decimal whose bits indicate L2/L3/L4/L7 capability.
func inferTypeFromSNMP(servicesStr, descr string) string {
	// sysServices bitmask (RFC 1213): 1=L2, 2=L3(IP), 4=L4, 8/TCP, 16/app
	// Heuristics mirroring the legacy inferTypeFromSysServices.
	sv := atoiSafe(servicesStr)
	lower := strings.ToLower(descr)
	switch {
	// Switch values (L2+L3+L4 = 78, L2+L3+L4+TCP = 76) come BEFORE the generic
	// server band (72-79) so they win.
	case sv == 78:
		return "switch"
	case sv == 76:
		return "switch"
	case sv == 6:
		// L3 device: router/firewall/nas — refine by description.
		if strings.Contains(lower, "firewall") || strings.Contains(lower, "fortigate") || strings.Contains(lower, "palo alto") {
			return "firewall"
		}
		if strings.Contains(lower, "nas") || strings.Contains(lower, "synology") || strings.Contains(lower, "qnap") {
			return "nas"
		}
		return "router"
	case sv >= 72 && sv <= 79:
		return "server"
	case strings.Contains(lower, "printer"):
		return "other"
	case strings.Contains(lower, "linux") || strings.Contains(lower, "windows"):
		return "server"
	}
	return ""
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

// enterpriseOIDPrefix maps the enterprise OID (1.3.6.1.4.1.<ent>) to a brand.
var enterpriseOIDPrefix = []struct {
	prefix string
	brand  string
}{
	{"1.3.6.1.4.1.9.", "Cisco"},
	{"1.3.6.1.4.1.11.", "HP"},
	{"1.3.6.1.4.1.674.", "Dell"},
	{"1.3.6.1.4.1.2011.", "Huawei"},
	{"1.3.6.1.4.1.2636.", "Juniper"},
	{"1.3.6.1.4.1.14823.", "Aruba"},
	{"1.3.6.1.4.1.30065.", "Mikrotik"},
	{"1.3.6.1.4.1.8072.", "NetSNMP"}, // generic — host runs net-snmp
	{"1.3.6.1.4.1.39165.", "Hikvision"},
	{"1.3.6.1.4.1.100484.", "Dahua"},
	{"1.3.6.1.4.1.368.", "Axis"},
	{"1.3.6.1.4.1.12325.", "Synology"},
	{"1.3.6.1.4.1.24681.", "QNAP"},
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
