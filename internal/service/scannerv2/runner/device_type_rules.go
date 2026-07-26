// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	_ "embed"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"

	"mibee-steward/internal/service/scannerv2"
)

// deviceTypesYAML is the data half of device-type inference (the logic half is
// matchDeviceType below). Embedded so the binary is self-contained and the
// table is version-controlled alongside the engine. Editing this YAML — not Go
// code — is how new device signatures are added. See device_types.yaml for the
// schema and ordering rules.
//
//go:embed device_types.yaml
var deviceTypesYAML string

// typeRuleTable is the parsed device_types.yaml: three ordered rule lists
// (host/brand keyword rules, OS-label rules, port-shape rules). All matching is
// case-insensitive (keywords and inputs are lowercased once at load/match time).
type typeRuleTable struct {
	Rules     []typeRule     `yaml:"rules"`
	OSRules   []osTypeRule   `yaml:"os_rules"`
	PortRules []portTypeRule `yaml:"port_rules"`
}

// typeRule matches a host/brand/hint substring keyword against a device type.
// Field selects the input string: "host" (rDNS hostname), "brand"
// (inferred_brand), or "hint" (host+" "+brand+" "+os — the broadest). The first
// rule whose field's value contains ANY keyword wins (the rules list is the
// priority order). Source is the confidence label ("heuristic" — these are all
// hostname/port guesses, spoofable) persisted to scan_attributes for UI display.
type typeRule struct {
	Type     string   `yaml:"type"`
	Field    string   `yaml:"field"`  // host | brand | hint
	Source   string   `yaml:"source"` // heuristic (the only value in the table)
	Keywords []string `yaml:"keywords"`
}

// osTypeRule matches an os_type label (from SSH/SNMP banner) keyword against a
// type. Run after host/brand rules. First-match-wins.
type osTypeRule struct {
	Keywords []string `yaml:"keywords"`
	Type     string   `yaml:"type"`
	Source   string   `yaml:"source"`
}

// portTypeRule is the port-shape fallback: infer a type from the open-port /
// classified-service set when no host/brand/os signal matched (the common
// cross-subnet case where only ICMP + rDNS + a few TCP ports survive).
//
//   - service: a classified service name that MUST be present (ssh/smb/rtsp/…).
//   - require: additional service names that MUST also be present (AND).
//   - port:    a single open port (used when the service went unclassified
//     because the banner timed out).
//   - port_any: any of these ports open.
//   - exclude_ports: ports that must NOT be open.
type portTypeRule struct {
	Service      string   `yaml:"service"`
	Require      []string `yaml:"require"`
	Port         int      `yaml:"port"`
	PortAny      []int    `yaml:"port_any"`
	ExcludePorts []int    `yaml:"exclude_ports"`
	Type         string   `yaml:"type"`
	Source       string   `yaml:"source"`
}

// deviceTypeRules is the loaded, lowercased table. Populated once by init() from
// the embedded YAML. Package-level because the table is immutable after load and
// shared by every matchDeviceType / isStrong*Signal call.
var deviceTypeRules typeRuleTable

func init() {
	if err := yaml.Unmarshal([]byte(deviceTypesYAML), &deviceTypeRules); err != nil {
		// A malformed embedded table is a build-time authoring error, not a
		// runtime condition — log loudly and fall back to an empty table (which
		// makes matchDeviceType return "" → "other", degrading gracefully rather
		// than panicking on startup).
		slog.Error("device_types.yaml parse failed; type inference disabled", "error", err)
		deviceTypeRules = typeRuleTable{}
		return
	}
	// Lowercase all keywords once so match-time comparison is allocation-free.
	for i := range deviceTypeRules.Rules {
		for j := range deviceTypeRules.Rules[i].Keywords {
			deviceTypeRules.Rules[i].Keywords[j] = strings.ToLower(deviceTypeRules.Rules[i].Keywords[j])
		}
	}
	for i := range deviceTypeRules.OSRules {
		for j := range deviceTypeRules.OSRules[i].Keywords {
			deviceTypeRules.OSRules[i].Keywords[j] = strings.ToLower(deviceTypeRules.OSRules[i].Keywords[j])
		}
	}
}

// matchDeviceType is the generic, data-driven device-type inference engine. It
// replaces the former ~145-line hardcoded switch in heuristicDeviceType: the
// keyword tables now live in device_types.yaml, and this function is the
// write-once priority matcher over them. Returns (type, source) where source is
// the confidence label from the matched rule ("heuristic" for all table rules —
// they're hostname/port guesses, spoofable). Returns ("", "") when nothing
// matches (the caller falls back to "other").
//
// Evaluation order (first match wins):
//  1. host/brand/hint keyword rules (device_types.yaml `rules:`)
//  2. os_type label rules (`os_rules:`)
//  3. port-shape fallback (`port_rules:`)
func matchDeviceType(rep scannerv2.HostReport) (string, string) {
	host := strings.ToLower(rep.Device.Fields["node_hostname"])
	if host == "" {
		host = strings.ToLower(rep.Device.Fields["sys_name"])
	}
	brand := strings.ToLower(rep.Device.Fields["inferred_brand"])
	osType := strings.ToLower(rep.Device.Fields["os_type"])
	hint := host + " " + brand + " " + osType

	// 1. host/brand/hint keyword rules (ordered — priority).
	for _, r := range deviceTypeRules.Rules {
		var field string
		switch r.Field {
		case "brand":
			field = brand
		case "hint":
			field = hint
		default: // "host" and anything else
			field = host
		}
		if containsAny(field, r.Keywords...) {
			return r.Type, r.Source
		}
	}

	// 2. os_type label rules (ordered).
	for _, r := range deviceTypeRules.OSRules {
		if containsAny(osType, r.Keywords...) {
			return r.Type, r.Source
		}
	}

	// 3. port-shape fallback.
	svcSet := make(map[string]bool, len(rep.Services))
	openPorts := make(map[int]bool, len(rep.Services))
	for _, s := range rep.Services {
		svcSet[s.Service] = true
		openPorts[s.Port] = true
	}
	hasPort := func(ports ...int) bool {
		for _, p := range ports {
			if openPorts[p] {
				return true
			}
		}
		return false
	}
	for _, r := range deviceTypeRules.PortRules {
		// Service-name conditions (service + optional require list) — all must hold.
		if r.Service != "" && !svcSet[r.Service] {
			continue
		}
		serviceOK := true
		for _, req := range r.Require {
			if !svcSet[req] {
				serviceOK = false
				break
			}
		}
		if !serviceOK {
			continue
		}
		// Port-number conditions.
		if r.Port != 0 && !openPorts[r.Port] {
			continue
		}
		if len(r.PortAny) > 0 && !hasPort(r.PortAny...) {
			continue
		}
		// Excluded ports — none may be open.
		excluded := false
		for _, p := range r.ExcludePorts {
			if openPorts[p] {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		// At least one positive condition must be set (otherwise an all-zero rule
		// would match everything). A rule with only service/require is positive.
		if r.Service == "" && r.Port == 0 && len(r.PortAny) == 0 {
			continue
		}
		return r.Type, r.Source
	}
	return "", ""
}

// keywordsForType returns the union of host+brand+hint keywords from
// device_types.yaml that resolve to the given type. Used by isStrongPcSignal /
// isStrongNasSignal so the override gates share ONE keyword source with the main
// inference engine (preventing the three-table drift that caused the earlier
// "z4s" mis-classification). Only host/brand/hint rules contribute (not os/port
// rules — those are weaker signals not suitable for overriding a camera verdict).
func keywordsForType(wantType string) []string {
	var out []string
	for _, r := range deviceTypeRules.Rules {
		if r.Type == wantType {
			out = append(out, r.Keywords...)
		}
	}
	return out
}

// sourceForType returns the confidence source label ("heuristic") for the first
// rule matching wantType in device_types.yaml. Used by the override branches in
// applyDeviceBridge (when isStrongPcSignal/isStrongNasSignal flip a camera to
// pc/nas) so the persisted source comes from the data table, not a hardcoded
// string. Falls back to "heuristic" (the only source the table uses) if no rule
// matches — the override wouldn't have fired without a matching keyword anyway.
func sourceForType(wantType string) string {
	for _, r := range deviceTypeRules.Rules {
		if r.Type == wantType && r.Source != "" {
			return r.Source
		}
	}
	for _, r := range deviceTypeRules.OSRules {
		if r.Type == wantType && r.Source != "" {
			return r.Source
		}
	}
	return "heuristic"
}
