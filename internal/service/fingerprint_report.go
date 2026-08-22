// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// FingerprintReportService builds the fingerprint-coverage report (#282):
// how well the identification stack (protocol evidence / heuristic keyword
// rules) is doing on this inventory, which devices remain unidentified, and
// how to turn one of them into a contribution — a validated YAML rule draft
// generated from the evidence the scanner already collected.
//
// The tiers read devices.scan_attributes (the engine-written discovery
// aggregation): inferred_type_source = "protocol" (SNMP/RTSP/ONVIF/mDNS
// evidence — trustworthy) / "heuristic" (hostname/brand keyword guess —
// spoofable, shown with a ? badge in the UI) / anything else with
// inferred_type resolving to "other" = unidentified.
type FingerprintReportService struct {
	queries *db.Queries
	dbtx    db.DBTX
}

func NewFingerprintReportService(queries *db.Queries, dbtx db.DBTX) *FingerprintReportService {
	return &FingerprintReportService{queries: queries, dbtx: dbtx}
}

// FingerprintCoverage is the payload of GET /api/v1/fingerprints/coverage.
type FingerprintCoverage struct {
	Total        int64                `json:"total"`
	Protocol     int64                `json:"protocol"`
	Heuristic    int64                `json:"heuristic"`
	Unidentified int64                `json:"unidentified"`
	Devices      []UnidentifiedDevice `json:"devices"`
	Groups       []UnidentifiedGroup  `json:"groups"`
}

// UnidentifiedDevice is one row of the unidentified list, enriched with the
// device's known services so the UI can show what evidence exists to build
// a rule from.
type UnidentifiedDevice struct {
	UUID      string `json:"device_uuid"`
	Name      string `json:"name"`
	IP        string `json:"ip_address"`
	MAC       string `json:"mac_address"`
	Hostname  string `json:"hostname"`
	Vendor    string `json:"vendor"`
	OUIVendor string `json:"oui_vendor"`
	OS        string `json:"os"`
	// Ports/Services come from host_services (the classified service set).
	Ports    []int    `json:"ports"`
	Services []string `json:"services"`
}

// UnidentifiedGroup clusters unidentified devices by a shared feature so the
// report can show "the TOP characteristics that need rules": one rule added
// for a signature may identify N devices at once.
type UnidentifiedGroup struct {
	Kind       string   `json:"kind"` // "oui" | "ports" | "hostname_prefix"
	Signature  string   `json:"signature"`
	Count      int      `json:"count"`
	ExampleIPs []string `json:"example_ips"`
}

// Coverage computes the tier stats + the unidentified list with groupings.
// scope filters the inventory to the caller's network grants (nil / global =
// every network — admin or open-mode rbac).
func (s *FingerprintReportService) Coverage(ctx context.Context, scope domain.Scope) (*FingerprintCoverage, error) {
	cov := &FingerprintCoverage{}
	netFilter, netArgs := networkFilter(scope)
	err := s.dbtx.QueryRowContext(ctx, `
		SELECT COUNT(*),
		  COALESCE(SUM(CASE WHEN json_extract(scan_attributes,'$.inferred_type_source')='protocol' THEN 1 ELSE 0 END),0),
		  COALESCE(SUM(CASE WHEN json_extract(scan_attributes,'$.inferred_type_source')='heuristic' THEN 1 ELSE 0 END),0),
		  COALESCE(SUM(CASE WHEN COALESCE(json_extract(scan_attributes,'$.inferred_type'),'other')='other' THEN 1 ELSE 0 END),0)
		FROM devices WHERE 1=1`+netFilter, netArgs...).Scan(&cov.Total, &cov.Protocol, &cov.Heuristic, &cov.Unidentified)
	if err != nil {
		return nil, fmt.Errorf("fingerprint coverage: %w", err)
	}

	rows, err := s.dbtx.QueryContext(ctx, `
		SELECT device_uuid, COALESCE(name,''), ip_address, COALESCE(mac_address,''),
		  COALESCE(json_extract(scan_attributes,'$.hostname'),''),
		  COALESCE(json_extract(scan_attributes,'$.vendor'),''),
		  COALESCE(json_extract(scan_attributes,'$.oui_vendor'),''),
		  COALESCE(json_extract(scan_attributes,'$.os'),'')
		FROM devices
		WHERE COALESCE(json_extract(scan_attributes,'$.inferred_type'),'other')='other'`+netFilter+`
		ORDER BY ip_address`, netArgs...)
	if err != nil {
		return nil, fmt.Errorf("fingerprint unidentified list: %w", err)
	}
	defer rows.Close()

	devs := []UnidentifiedDevice{}
	for rows.Next() {
		var d UnidentifiedDevice
		if err := rows.Scan(&d.UUID, &d.Name, &d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.OUIVendor, &d.OS); err != nil {
			return nil, err
		}
		devs = append(devs, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(devs) > 0 {
		if err := s.attachServices(ctx, devs); err != nil {
			return nil, err
		}
	}
	// Never ship nil slices: encoding/json renders nil as JSON null, and the
	// UI's .join()/.length on null throws mid-render (the whole coverage
	// section goes blank). Empty arrays instead.
	for i := range devs {
		if devs[i].Ports == nil {
			devs[i].Ports = []int{}
		}
		if devs[i].Services == nil {
			devs[i].Services = []string{}
		}
	}
	cov.Devices = devs
	cov.Groups = groupUnidentified(devs)
	if cov.Groups == nil {
		cov.Groups = []UnidentifiedGroup{}
	}
	return cov, nil
}

// attachServices fills Ports/Services from host_services for the given
// unidentified devices (matched by IP — the service table's stable key).
func (s *FingerprintReportService) attachServices(ctx context.Context, devs []UnidentifiedDevice) error {
	ips := make([]string, len(devs))
	byIP := map[string]*UnidentifiedDevice{}
	for i := range devs {
		ips[i] = devs[i].IP
		byIP[devs[i].IP] = &devs[i]
	}
	placeholders := strings.Repeat("?,", len(ips))
	args := make([]any, len(ips))
	for i, ip := range ips {
		args[i] = ip
	}
	rows, err := s.dbtx.QueryContext(ctx,
		fmt.Sprintf("SELECT ip, service, port FROM host_services WHERE ip IN (%s)", placeholders[:len(placeholders)-1]),
		args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip, svc string
		var port int
		if err := rows.Scan(&ip, &svc, &port); err != nil {
			return err
		}
		if d, ok := byIP[ip]; ok {
			d.Ports = append(d.Ports, port)
			d.Services = append(d.Services, svc)
		}
	}
	return rows.Err()
}

// groupUnidentified clusters by OUI vendor, port signature, and hostname
// prefix (first label), keeping the TOP groups of each kind.
func groupUnidentified(devs []UnidentifiedDevice) []UnidentifiedGroup {
	count := map[string]*UnidentifiedGroup{}
	add := func(kind, sig string, ip string) {
		key := kind + ":" + sig
		g, ok := count[key]
		if !ok {
			g = &UnidentifiedGroup{Kind: kind, Signature: sig}
			count[key] = g
		}
		g.Count++
		if len(g.ExampleIPs) < 3 {
			g.ExampleIPs = append(g.ExampleIPs, ip)
		}
	}
	for _, d := range devs {
		if d.OUIVendor != "" {
			add("oui", d.OUIVendor, d.IP)
		}
		if len(d.Ports) > 0 {
			ports := append([]int(nil), d.Ports...)
			sort.Ints(ports)
			parts := make([]string, len(ports))
			for i, p := range ports {
				parts[i] = fmt.Sprintf("%d", p)
			}
			add("ports", strings.Join(parts, ","), d.IP)
		}
		if d.Hostname != "" {
			first := strings.SplitN(d.Hostname, ".", 2)[0]
			if len(first) >= 3 { // too-short prefixes would over-merge
				add("hostname_prefix", strings.ToLower(first), d.IP)
			}
		}
	}
	groups := make([]UnidentifiedGroup, 0, len(count))
	for _, g := range count {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Count > groups[j].Count })
	if len(groups) > 15 {
		groups = groups[:15]
	}
	return groups
}

// networkFilter renders the WHERE fragment restricting devices to the
// caller's granted networks. Empty string + nil args = unfiltered.
func networkFilter(scope domain.Scope) (string, []any) {
	if scope.IsGlobal() || len(scope.NetworkIDs) == 0 {
		return "", nil
	}
	placeholders := strings.Repeat("?,", len(scope.NetworkIDs))
	args := make([]any, len(scope.NetworkIDs))
	for i, id := range scope.NetworkIDs {
		args[i] = id
	}
	return " AND network_id IN (" + placeholders[:len(placeholders)-1] + ")", args
}

// --- Rule draft generation ---

// draftRule mirrors the fingerprint rule YAML schema (subset the generator
// emits). Round-trips through yaml.v3 with the same field names as
// mibee-fingerprints-go's ruleFile.
type draftRule struct {
	ID     string `yaml:"id"`
	Source string `yaml:"source"`
	Match  struct {
		Kind  string `yaml:"kind"`
		Field string `yaml:"field"`
		Op    string `yaml:"op"`
		Value string `yaml:"value"`
		CI    bool   `yaml:"ci"`
	} `yaml:"match"`
	Service    string            `yaml:"service"`
	Protocol   string            `yaml:"protocol,omitempty"`
	Confidence float64           `yaml:"confidence"`
	Extract    *draftRuleExtract `yaml:"extract,omitempty"`
}

type draftRuleExtract struct {
	DeviceType string `yaml:"device_type,omitempty"`
}

type draftRuleFile struct {
	Version int         `yaml:"version"`
	Rules   []draftRule `yaml:"rules"`
}

// evidenceRow is one service_evidence row relevant to draft generation.
type evidenceRow struct {
	Kind    string
	Port    int
	RawData map[string]string
}

// portServiceHints maps well-known ports to the service name used by the
// classifier stack — used to pre-fill the draft's service field.
var portServiceHints = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 443: "https",
	465: "smtps", 554: "rtsp", 587: "smtp", 636: "ldaps", 993: "imaps",
	995: "pop3s", 2020: "http", 8000: "http", 8080: "http", 8443: "https",
	8899: "http", 9443: "https", 5000: "upnp", 1900: "upnp", 5353: "mdns",
}

// RuleDraft generates a validated fingerprint-rule YAML draft for one
// unidentified device, built from the evidence the scanner already collected
// (SNMP sysDescr, TCP banners, HTTP title/server). The returned YAML parses
// AND compiles through the real rule classifier (LoadFromDir on a temp dir),
// so what the contributor downloads is guaranteed syntactically loadable —
// they only fill in the service/device_type judgment calls.
func (s *FingerprintReportService) RuleDraft(ctx context.Context, deviceUUID string, scope domain.Scope) (string, error) {
	var ip string
	var networkID sql.NullInt64
	err := s.dbtx.QueryRowContext(ctx,
		`SELECT ip_address, network_id FROM devices WHERE device_uuid = ?`, deviceUUID).Scan(&ip, &networkID)
	if err != nil {
		return "", fmt.Errorf("device not found: %w", err)
	}
	if !scope.IsGlobal() && (!networkID.Valid || !scope.AllowsNetwork(networkID.Int64)) {
		return "", fmt.Errorf("device out of network scope")
	}

	rows, err := s.dbtx.QueryContext(ctx, `
		SELECT kind, port, raw_data FROM service_evidence
		WHERE (device_uuid = ? OR (device_uuid = '' AND ip = ?))
		  AND kind IN ('banner','http','snmp','rtsp')
		ORDER BY observed_at DESC LIMIT 50`, deviceUUID, ip)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	ev := []evidenceRow{}
	for rows.Next() {
		var e evidenceRow
		var raw []byte
		if err := rows.Scan(&e.Kind, &e.Port, &raw); err != nil {
			return "", err
		}
		rd := map[string]string{}
		_ = yaml.Unmarshal(raw, &rd)
		e.RawData = rd
		ev = append(ev, e)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	draft := draftRuleFile{Version: 1}
	seen := map[string]bool{}
	for _, e := range ev {
		var r *draftRule
		switch e.Kind {
		case "snmp":
			if v := significantToken(e.RawData["sys_descr"], 24); v != "" {
				r = newDraftRule("snmp", "sys_descr", v, "snmp", e.Port, 0.9)
			}
		case "banner":
			if v := significantToken(e.RawData["banner"], 20); v != "" {
				r = newDraftRule("banner", "banner", v, portServiceHints[e.Port], e.Port, 0.9)
			}
		case "http":
			for _, f := range []string{"title", "server"} {
				if v := significantToken(e.RawData[f], 16); v != "" {
					r = newDraftRule("http", f, v, portServiceHints[e.Port], e.Port, 0.85)
					break
				}
			}
		case "rtsp":
			if v := significantToken(e.RawData["server"], 16); v != "" {
				r = newDraftRule("rtsp", "server", v, "rtsp", e.Port, 0.9)
			}
		}
		if r == nil || seen[r.Match.Value] {
			continue
		}
		seen[r.Match.Value] = true
		draft.Rules = append(draft.Rules, *r)
	}

	if len(draft.Rules) == 0 {
		// No usable evidence — hand back the explanatory header alone so the
		// contributor still gets the "how to contribute" pointers.
		return draftHeader + draftNoRulesNote, nil
	}

	body, err := yaml.Marshal(&draft)
	if err != nil {
		return "", err
	}
	out := draftHeader + string(body)

	if err := validateDraft(out); err != nil {
		return "", fmt.Errorf("generated draft failed validation: %w", err)
	}
	return out, nil
}

func newDraftRule(kind, field, value, service string, _ int, confidence float64) *draftRule {
	r := &draftRule{
		ID:      fmt.Sprintf("draft-%s-%s", kind, strings.ToLower(strings.ReplaceAll(value, " ", "-"))),
		Service: service, Protocol: "tcp",
		Confidence: confidence,
	}
	r.Source = "community-draft"
	r.Match.Kind = kind
	r.Match.Field = field
	r.Match.Op = "contains"
	r.Match.CI = true
	r.Match.Value = value
	if service == "" {
		r.Service = "TODO"
	}
	if kind == "snmp" {
		r.Protocol = "udp"
	}
	return r
}

// significantToken picks a stable, distinctive substring from raw evidence
// text: trimmed, capped at maxLen, empty when too generic to be a rule value.
func significantToken(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) < 4 {
		return ""
	}
	// Skip pure generics that would over-match: protocol greetings, "Server"
	// alone, version-only strings.
	generics := []string{"HTTP", "SSH-", "RTSP/", "Server", "nginx", "Apache", "LiteSpeed"}
	for _, g := range generics {
		if s == g || strings.HasPrefix(s, g) && len(s) <= len(g)+1 {
			return ""
		}
	}
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	// A value with YAML-problematic characters is still fine (yaml.Marshal
	// quotes as needed); but strip control chars that come from banners.
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

const draftHeader = `# MiBee Steward fingerprint rule draft (auto-generated — #282 contribution loop).
#
# This file PARSES AND COMPILES as-is — fill in the TODOs (service name),
# tune the match values, then contribute it:
#   1. Edit rules: pick the distinctive token for your device (see
#      docs/en/fingerprint-spec.md for the match/extract grammar).
#   2. Validate: this draft already compiles through the live rule
#      classifier; re-check after edits by re-importing in MiBee.
#   3. Contribute: PR against configs/fingerprints/ (CC-BY-SA 4.0 corpus).
#
# Generated from live scan evidence — match values are real observations
# from your network.

`

const draftNoRulesNote = `# No banner / HTTP / SNMP / RTSP evidence is stored for this device, so no
# rule could be pre-filled. Trigger a scan of this IP first (scanner → scan),
# then generate the draft again — evidence older than the retention window
# (default 14d) is pruned.
`

// validateDraft round-trips the generated YAML through the REAL rule
// classifier (temp dir + LoadFromDir) — parse + compileMatch both run.
func validateDraft(yamlText string) error {
	dir, err := os.MkdirTemp("", "mibee-fp-draft-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "draft.yaml"), []byte(yamlText), 0o600); err != nil {
		return err
	}
	rc := &fp.RuleClassifier{}
	if err := rc.LoadFromDir(dir); err != nil {
		return err
	}
	if !rc.Loaded() || rc.RuleCount() == 0 {
		return fmt.Errorf("draft compiled to zero rules")
	}
	return nil
}
