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
	_ "embed"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"

	"mibee-steward/internal/service/scannerv2"
)

// snmpDataYAML is the data half of SNMPClassifier (the logic half is the Go
// functions below). It mirrors configs/fingerprints/snmp-data.yaml via the
// sync-fingerprints make target (copied to fingerprint-assets/ at build time).
// Editing this YAML — not Go code — is how new vendor OIDs, sysDescr keywords,
// brand keywords, or OS labels are added. This is the same data-driven pattern
// runner/device_type_rules.go uses for device-type inference.
//
// Before this refactor the same data lived as Go literals (enterpriseOIDPrefix,
// the typeFromSysDescr switch, etc.) AND as this YAML, with the YAML a dead
// copy — so the two had already drifted (the YAML's oid_prefixes table has 13
// more consumer/SMB vendors than the old Go table did). The YAML is now the
// single source of truth.
//
//go:embed fingerprint-assets/snmp-data.yaml
var snmpDataYAML string

// snmpData is the parsed snmp-data.yaml, populated once by init(). Package-level
// because the tables are immutable after load and shared by every SNMPClassifier
// call. All keyword matching is case-insensitive (keywords and inputs are
// lowercased once at load/match time).
var snmpData snmpDataTables

type snmpDataTables struct {
	OIDPrefixes    []oidPrefixRule     `yaml:"oid_prefixes"`
	SysdescrTypes  []sysdescrTypeRule  `yaml:"sysdescr_types"`
	SysdescrBrands []sysdescrBrandRule `yaml:"sysdescr_brands"`
	SysdescrOS     []sysdescrOSRule    `yaml:"sysdescr_os"`
}

// oidPrefixRule maps a sysObjectID enterprise OID prefix to a brand and (optionally)
// a device type. Order matters: more-specific prefixes must precede their general
// parent (e.g. 9.1.300 before 9.1 before 9) — typeFromOID returns on the first
// HasPrefix hit. `type` may be empty when the OID alone can't tell (e.g. Net-SNMP
// 8072 runs on anything).
type oidPrefixRule struct {
	Prefix string `yaml:"prefix"`
	Brand  string `yaml:"brand"`
	Type   string `yaml:"type"`
}

// sysdescrTypeRule matches a sysDescr substring keyword (case-insensitive) to a
// device type. Ordered — first match wins. Mirrors the original typeFromSysDescr
// switch order.
type sysdescrTypeRule struct {
	Keywords []string `yaml:"keywords"`
	Type     string   `yaml:"type"`
}

// sysdescrBrandRule matches a sysDescr substring keyword to a vendor brand.
// Case-insensitive contains; first hit wins; falls back to the OID table.
type sysdescrBrandRule struct {
	Keyword string `yaml:"keyword"`
	Brand   string `yaml:"brand"`
}

// sysdescrOSRule matches a sysDescr substring keyword to a normalized OS family
// label. Ordered — first match wins.
type sysdescrOSRule struct {
	Keywords []string `yaml:"keywords"`
	OS       string   `yaml:"os"`
}

func init() {
	if err := yaml.Unmarshal([]byte(snmpDataYAML), &snmpData); err != nil {
		// A malformed embedded table is a build-time authoring error, not a
		// runtime condition — log loudly and fall back to empty tables (which
		// makes the SNMP classifier return no type/brand/OS, degrading
		// gracefully rather than panicking on startup).
		slog.Error("snmp-data.yaml parse failed; SNMP type/brand/os inference disabled", "error", err)
		snmpData = snmpDataTables{}
		return
	}
	// Lowercase all keywords once so match-time comparison is allocation-free.
	for i := range snmpData.SysdescrTypes {
		for j := range snmpData.SysdescrTypes[i].Keywords {
			snmpData.SysdescrTypes[i].Keywords[j] = strings.ToLower(snmpData.SysdescrTypes[i].Keywords[j])
		}
	}
	for i := range snmpData.SysdescrBrands {
		snmpData.SysdescrBrands[i].Keyword = strings.ToLower(snmpData.SysdescrBrands[i].Keyword)
	}
	for i := range snmpData.SysdescrOS {
		for j := range snmpData.SysdescrOS[i].Keywords {
			snmpData.SysdescrOS[i].Keywords[j] = strings.ToLower(snmpData.SysdescrOS[i].Keywords[j])
		}
	}
}

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
//
// Stages 1 and 2 are data-driven (snmp-data.yaml's oid_prefixes +
// sysdescr_types tables). Stage 3 is the documented logic-plugin — the bitmask
// × ifNumber heuristic CANNOT be expressed as declarative rules (see
// docs/en/fingerprint-spec.md §"Logic plugins") and stays as Go code.
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

// typeFromOID maps a sysObjectID enterprise prefix to a device type, loaded from
// snmp-data.yaml's oid_prefixes table. Vendor OIDs encode device class far more
// reliably than sysServices — e.g. Cisco routers live under 9.1.1, Catalyst
// switches under 9.1.300+, HP ProCurve under 11.2.3.7.11. Returns "" for
// unknown/generic OIDs (e.g. Net-SNMP 8072). Iterates the table in declared
// order; more-specific prefixes must precede their general parent.
func typeFromOID(objID string) string {
	if objID == "" {
		return ""
	}
	for _, e := range snmpData.OIDPrefixes {
		if strings.HasPrefix(objID, e.Prefix) {
			return e.Type
		}
	}
	return ""
}

// typeFromSysDescr matches known OS/product strings in sysDescr to a type,
// loaded from snmp-data.yaml's sysdescr_types table (ordered, first-match-wins,
// case-insensitive). Covers the common network-OS and NAS/appliance descriptors.
func typeFromSysDescr(lower string) string {
	for _, r := range snmpData.SysdescrTypes {
		if containsAny(lower, r.Keywords...) {
			return r.Type
		}
	}
	return ""
}

// osFromSysDescr extracts a normalized OS family string from the sysDescr text,
// loaded from snmp-data.yaml's sysdescr_os table (ordered, first-match-wins,
// case-insensitive). The OS is orthogonal to type (a Linux box could be a
// server, a camera, or a router); the result feeds scan_attributes.os so
// SNMP-reachable devices get a populated OS even when no
// node_exporter/SSDP/NetBIOS signal exists.
func osFromSysDescr(lower string) string {
	for _, r := range snmpData.SysdescrOS {
		if containsAny(lower, r.Keywords...) {
			return r.OS
		}
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

// inferBrand extracts a vendor name from sysDescr keywords (snmp-data.yaml's
// sysdescr_brands table, case-insensitive) or, failing that, the enterprise OID
// prefix in sysObjectID (the oid_prefixes table).
func inferBrand(descr, objID string) string {
	lower := strings.ToLower(descr)
	for _, r := range snmpData.SysdescrBrands {
		if strings.Contains(lower, r.Keyword) {
			return r.Brand
		}
	}
	// Enterprise OID prefix lookup.
	return brandFromOID(objID)
}

// brandFromOID maps a sysObjectID enterprise prefix to a brand via the
// oid_prefixes table. Returns "" for unknown OIDs.
func brandFromOID(objID string) string {
	if objID == "" {
		return ""
	}
	for _, e := range snmpData.OIDPrefixes {
		if strings.HasPrefix(objID, e.Prefix) {
			return e.Brand
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
