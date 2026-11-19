// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Package diagnostics classifies per-device network anomalies (#761) from
// data the scan/report pipelines already persist. It is a pure read-model:
// no schema, no writes. The classifier's shapes are field-verified against
// the 2026-11-19 incident where one offline box split into four device rows
// with sightings at ~30 addresses that never answered on the wire — sightings
// ALONE are ambiguous (they record what a vantage observed, including stale
// ARP-cache reads), so every address is cross-checked against the scan
// snapshot's liveness facts before a verdict is issued.
package diagnostics

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// ErrDeviceNotFound is returned when the device id does not resolve.
var ErrDeviceNotFound = errors.New("device not found")

// Classifier thresholds. Field-tuned on the incident corpus: the ghost box
// accumulated 30 addresses over 15 minutes while a normal roamer holds 1-2
// and a dual-homed host keeps every address alive.
const (
	sightingsLimit = 500
	changeLimit    = 50
	// maxNetworks bounds the snapshot fan-out on multi-segment sightings.
	maxNetworks = 8
	// minArtifactAddresses: at least this many distinct addresses for the
	// stale-ARP pattern (fewer than 3 = ordinary roam/dual-homed territory).
	minArtifactAddresses = 3
	// minArtifactDead: at least this many observed addresses carry no live
	// scan hit. Ghost sightings point at addresses that never answer.
	minArtifactDead = 2
)

// Service diagnoses device network anomalies from persisted scan facts.
type Service struct {
	dbConn  *sql.DB
	queries *db.Queries
	now     func() time.Time
}

// NewService constructs the diagnosis service over the center's database.
// The raw *sql.DB is kept beside the sqlc handle because two of the reads
// (sibling rows by hostname, per-IP liveness) must run as raw SQL: sqlc's
// SQLite parser truncates their trailing statements (the same documented
// parser bug that forced ListStaleAgentSnapshots and the CASE-WHEN snapshot
// upsert to raw SQL elsewhere).
func NewService(dbConn *sql.DB) *Service {
	return &Service{dbConn: dbConn, queries: db.New(dbConn), now: time.Now}
}

// Diagnose builds the verdict for one device: aggregated address timeline
// with per-address liveness, classified findings with evidence, and sibling
// rows announcing the same hostname.
func (s *Service) Diagnose(ctx context.Context, deviceID int64) (*domain.DeviceNetworkDiagnosis, error) {
	dev, err := s.queries.GetDevice(ctx, deviceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("load device: %w", err)
	}

	sightings, err := s.queries.ListDeviceSightings(ctx, db.ListDeviceSightingsParams{
		DeviceID: deviceID,
		Column2:  "", // empty vantage filter = every stream
		Vantage:  "",
		Limit:    sightingsLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("load sightings: %w", err)
	}

	presences, err := s.queries.ListDevicePresences(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("load presences: %w", err)
	}

	changes, err := s.queries.ListDeviceChangeHistory(ctx, db.ListDeviceChangeHistoryParams{
		EntityID: &deviceID,
		Limit:    changeLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("load change history: %w", err)
	}

	attrs, _ := domain.UnmarshalScanAttributes(dev.ScanAttributes)

	addrs := aggregateAddresses(sightings)
	markLiveness(ctx, s.dbConn, addrs, networksOf(dev, sightings))
	siblings := s.loadSiblings(ctx, deviceID, attrs.Hostname)

	out := &domain.DeviceNetworkDiagnosis{
		DeviceID:     dev.ID,
		DeviceName:   dev.Name,
		DeviceMAC:    dev.MacAddress,
		DeviceIP:     dev.IpAddress,
		DeviceStatus: dev.Status,
		Addresses:    toDomainAddresses(addrs, dev.IpAddress),
		Siblings:     siblings,
		GeneratedAt:  s.now(),
	}
	classify(out, dev, attrs, addrs, presences, changes)
	return out, nil
}

// addrAgg is the per-address accumulation of sighting rows, later annotated
// with scan-snapshot liveness facts.
type addrAgg struct {
	ip       string
	networks []int64
	macs     []string
	sources  []string
	vantages []string
	seeCount int64
	first    time.Time
	last     time.Time
	// Liveness facts (from scan_snapshots). alive = a snapshot exists with
	// miss_count == 0 (the address answered the latest scan). miss = -1 when
	// no snapshot row exists at all (never seen alive by a scan); flap = -1
	// means unknown.
	alive bool
	miss  int
	flap  int
}

func aggregateAddresses(rows []db.ListDeviceSightingsRow) []*addrAgg {
	byIP := map[string]*addrAgg{}
	var order []*addrAgg // newest-first, matching the sighting order
	for _, r := range rows {
		if r.IpAddress == "" {
			continue // MAC-only anchor sightings (#anchor:) carry no address
		}
		a, ok := byIP[r.IpAddress]
		if !ok {
			a = &addrAgg{ip: r.IpAddress, first: r.FirstSeen, last: r.LastSeen, miss: -1, flap: -1}
			byIP[r.IpAddress] = a
			order = append(order, a)
		}
		if r.FirstSeen.Before(a.first) {
			a.first = r.FirstSeen
		}
		if r.LastSeen.After(a.last) {
			a.last = r.LastSeen
		}
		a.seeCount += r.SeeCount
		a.networks = addUniqueI64(a.networks, r.NetworkID)
		if r.MacAddress != "" {
			a.macs = addUniqueStr(a.macs, strings.ToLower(r.MacAddress))
		}
		if r.Source != "" {
			a.sources = addUniqueStr(a.sources, r.Source)
		}
		a.vantages = addUniqueStr(a.vantages, r.Vantage)
	}
	return order
}

// snapshotLivenessSQL reads the per-IP liveness facts directly (raw SQL: the
// sqlc sqlite parser truncates this statement, see NewService).
const snapshotLivenessSQL = `SELECT ip, miss_count, flap_count FROM scan_snapshots WHERE network_id = ?`

// markLiveness annotates each address with the scan snapshot's facts.
// Sightings record what a vantage OBSERVED (including stale ARP-cache reads);
// the snapshot records whether the address actually ANSWERED a scan — the
// fact dimension that separates a live dual-homed host from a stale-cache
// ghost. Snapshot load failures degrade gracefully (facts stay unknown, the
// stale-artifact rule simply won't fire on missing data).
func markLiveness(ctx context.Context, conn *sql.DB, addresses []*addrAgg, networks []int64) {
	type snap struct {
		miss int64
		flap int64
	}
	snaps := map[string]snap{}
	for _, netID := range networks {
		rows, err := conn.QueryContext(ctx, snapshotLivenessSQL, netID)
		if err != nil {
			continue
		}
		for rows.Next() {
			var r snap
			var ip string
			if err := rows.Scan(&ip, &r.miss, &r.flap); err != nil {
				continue
			}
			snaps[fmt.Sprintf("%d|%s", netID, ip)] = r
		}
		rows.Close()
	}
	for _, a := range addresses {
		for _, netID := range a.networks {
			s, ok := snaps[fmt.Sprintf("%d|%s", netID, a.ip)]
			if !ok {
				continue
			}
			if s.miss == 0 {
				a.alive = true
			}
			// Best (minimum) miss streak across networks; -1 stays until the
			// first snapshot row proves the address was ever seen alive.
			if a.miss < 0 || s.miss < int64(a.miss) {
				a.miss = int(s.miss)
			}
			if s.flap > int64(a.flap) {
				a.flap = int(s.flap)
			}
		}
	}
}

// findSiblingsSQL lists device rows announcing the same hostname under a
// different MAC (raw SQL: the sqlc sqlite parser truncates this statement,
// see NewService).
const findSiblingsSQL = `
SELECT id, name, status, ip_address, mac_address, scan_hostname,
       COALESCE(network_id, 0), last_seen
FROM devices
WHERE scan_hostname = ? AND scan_hostname != '' AND id != ?
ORDER BY last_seen DESC
LIMIT 20`

func (s *Service) loadSiblings(ctx context.Context, deviceID int64, hostname string) []domain.DiagnosisSibling {
	if hostname == "" {
		return nil
	}
	rows, err := s.dbConn.QueryContext(ctx, findSiblingsSQL, hostname, deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]domain.DiagnosisSibling, 0, 4)
	for rows.Next() {
		var r domain.DiagnosisSibling
		var hostnameVal sql.NullString
		var lastSeen sql.NullTime
		if err := rows.Scan(&r.ID, &r.Name, &r.Status, &r.IPAddress, &r.MAC,
			&hostnameVal, &r.NetworkID, &lastSeen); err != nil {
			continue
		}
		r.Hostname = hostnameVal.String
		if lastSeen.Valid {
			t := lastSeen.Time
			r.LastSeen = &t
		}
		out = append(out, r)
	}
	return out
}

// classify runs the finding rules and derives the overall verdict.
func classify(out *domain.DeviceNetworkDiagnosis, dev db.Device, attrs domain.ScanAttributes,
	addrs []*addrAgg, presences []db.DeviceNetworkPresence, changes []db.ChangeLog) {

	var findings []domain.DiagnosisFinding

	// 1. Stale-ARP scan artifact: many addresses, one MAC, addresses that
	// never answer a scan — the field signature of the ghost-row family.
	macSet := map[string]bool{}
	for _, a := range addrs {
		for _, m := range a.macs {
			macSet[m] = true
		}
	}
	dead := []*addrAgg{}
	for _, a := range addrs {
		if !a.alive && a.ip != dev.IpAddress {
			dead = append(dead, a)
		}
	}
	if len(addrs) >= minArtifactAddresses && len(dead) >= minArtifactDead && len(macSet) == 1 {
		sev := domain.DiagnosisSeverityWarning
		if dev.Status != "online" || !currentAlive(addrs, dev.IpAddress) {
			sev = domain.DiagnosisSeverityCritical
		}
		ev := []domain.DiagnosisEvidence{{
			Kind:   "sighting",
			Detail: fmt.Sprintf("single MAC %s observed at %d distinct addresses", dev.MacAddress, len(addrs)),
		}}
		for _, a := range dead {
			detail := fmt.Sprintf("%s seen %d times until %s, no live scan response",
				a.ip, a.seeCount, a.last.UTC().Format(time.RFC3339))
			switch {
			case a.miss > 0:
				detail += fmt.Sprintf(" (missing %d consecutive scans)", a.miss)
			case a.miss < 0:
				detail += " (never seen alive by a scan)"
			}
			at := a.last
			ev = append(ev, domain.DiagnosisEvidence{Kind: "snapshot", Detail: detail, At: &at})
		}
		if dev.Status != "online" {
			ev = append(ev, domain.DiagnosisEvidence{Kind: "attribute",
				Detail: "device row status is " + dev.Status})
		}
		findings = append(findings, domain.DiagnosisFinding{
			Code:     domain.DiagnosisStaleARPArtifact,
			Severity: sev,
			Summary: fmt.Sprintf("One MAC observed at %d addresses, %d of which have no live scan response — "+
				"address drift is a stale ARP-cache artifact, not real churn.", len(addrs), len(dead)),
			Evidence: ev,
		})
	}

	// 2. Multi-homed alias: fresh presence in more than one network, or the
	// engine-recorded ip_aliases. Dual-homed bridging, not drift.
	if len(presences) > 1 {
		netSet := map[int64]bool{}
		ev := make([]domain.DiagnosisEvidence, 0, len(presences))
		for _, p := range presences {
			netSet[p.NetworkID] = true
			at := p.LastSeen
			ev = append(ev, domain.DiagnosisEvidence{Kind: "presence",
				Detail: fmt.Sprintf("active in network %d at %s", p.NetworkID, p.IpAddress), At: &at})
		}
		findings = append(findings, domain.DiagnosisFinding{
			Code:     domain.DiagnosisMultihomedAlias,
			Severity: domain.DiagnosisSeverityInfo,
			Summary: fmt.Sprintf("Asset actively present in %d networks — dual-homed or bridging, "+
				"one identity is correct.", len(netSet)),
			Evidence: ev,
		})
	} else if aliases := attrs.Extras["ip_aliases"]; aliases != "" {
		findings = append(findings, domain.DiagnosisFinding{
			Code:     domain.DiagnosisMultihomedAlias,
			Severity: domain.DiagnosisSeverityInfo,
			Summary:  "Engine recorded alias addresses for this MAC — a multi-address host, not drift.",
			Evidence: []domain.DiagnosisEvidence{{Kind: "attribute", Detail: "ip_aliases: " + aliases}},
		})
	}

	// 3. Locally-administered MAC: neutral fact, but MAC-based IP binding /
	// firewall rules will not stick for such an interface.
	if attrs.MacIsLocallyAdministered || hasLocalBit(dev.MacAddress) {
		findings = append(findings, domain.DiagnosisFinding{
			Code:     domain.DiagnosisLocallyAdministeredMAC,
			Severity: domain.DiagnosisSeverityInfo,
			Summary: "Identity MAC carries the locally-administered (U/L) bit — a virtual/soft MAC " +
				"(VM, container, VPN); MAC-based binding will not hold.",
			Evidence: []domain.DiagnosisEvidence{{Kind: "attribute",
				Detail: "MAC " + dev.MacAddress + " has the U/L bit set"}},
		})
	}

	// 4. IP-slot takeover: the change stream saw the MAC replaced at an
	// unchanged address — board swap, fresh DHCP identity, or spoofing.
	for _, c := range changes {
		if c.ChangeType != "device_changed" || c.BeforeData == nil || c.AfterData == nil {
			continue
		}
		var before, after map[string]any
		if json.Unmarshal([]byte(*c.BeforeData), &before) != nil ||
			json.Unmarshal([]byte(*c.AfterData), &after) != nil {
			continue
		}
		oldMAC, newMAC := jsonStr(before, "mac_address"), jsonStr(after, "mac_address")
		oldIP, newIP := jsonStr(before, "ip_address"), jsonStr(after, "ip_address")
		if oldIP == "" || oldIP != newIP || oldMAC == "" || newMAC == "" || oldMAC == newMAC {
			continue
		}
		at := c.DetectedAt
		findings = append(findings, domain.DiagnosisFinding{
			Code:     domain.DiagnosisIPSlotTakeover,
			Severity: domain.DiagnosisSeverityWarning,
			Summary: fmt.Sprintf("Identity replaced at address %s (%s → %s) — another device took over the slot.",
				oldIP, oldMAC, newMAC),
			Evidence: []domain.DiagnosisEvidence{{Kind: "change",
				Detail: fmt.Sprintf("device_changed at %s: mac %s → %s", oldIP, oldMAC, newMAC), At: &at}},
		})
	}

	// 5. Hostname identity split: sibling rows announcing the same hostname.
	if len(out.Siblings) > 0 {
		ev := make([]domain.DiagnosisEvidence, 0, len(out.Siblings))
		for _, sib := range out.Siblings {
			ev = append(ev, domain.DiagnosisEvidence{Kind: "sibling",
				Detail: fmt.Sprintf("row #%d (%s) at %s, mac %s, status %s",
					sib.ID, sib.Name, sib.IPAddress, macOr(sib.MAC, "unknown"), sib.Status)})
		}
		findings = append(findings, domain.DiagnosisFinding{
			Code:     domain.DiagnosisHostnameSplit,
			Severity: domain.DiagnosisSeverityInfo,
			Summary: fmt.Sprintf("%d other rows announce the hostname %q under different MACs — "+
				"one physical box split across identity rows.", len(out.Siblings), attrs.Hostname),
			Evidence: ev,
		})
	}

	out.Findings = findings
	out.Classification, out.Confidence, out.Status, out.Summary = verdict(findings)
}

// verdict picks the overall classification from the finding set.
func verdict(findings []domain.DiagnosisFinding) (domain.DiagnosisFindingCode, string, string, string) {
	rank := func(s domain.DiagnosisSeverity) int {
		switch s {
		case domain.DiagnosisSeverityCritical:
			return 3
		case domain.DiagnosisSeverityWarning:
			return 2
		default:
			return 1
		}
	}
	top := -1
	var topF *domain.DiagnosisFinding
	for i := range findings {
		if r := rank(findings[i].Severity); r > top {
			top = r
			topF = &findings[i]
		}
	}
	if topF == nil {
		return "", "", "healthy", "No address-drift or identity anomaly observed."
	}
	confidence := "medium"
	if topF.Code == domain.DiagnosisStaleARPArtifact {
		confidence = "high" // rests on per-address liveness facts, not sighting shape alone
	}
	status := "watch"
	if top >= 2 {
		status = "anomaly"
	}
	return topF.Code, confidence, status, topF.Summary
}

// --- small helpers -------------------------------------------------------

func toDomainAddresses(addrs []*addrAgg, currentIP string) []domain.DiagnosisAddress {
	out := make([]domain.DiagnosisAddress, 0, len(addrs))
	for _, a := range addrs {
		d := domain.DiagnosisAddress{
			IPAddress:    a.ip,
			MACs:         a.macs,
			Alive:        a.alive,
			MissingScans: a.miss,
			FlapCount:    a.flap,
			SeeCount:     a.seeCount,
			FirstSeen:    a.first,
			LastSeen:     a.last,
			Sources:      a.sources,
			Vantages:     a.vantages,
			Current:      a.ip == currentIP,
		}
		if d.MACs == nil {
			d.MACs = []string{}
		}
		if d.Sources == nil {
			d.Sources = []string{}
		}
		if d.Vantages == nil {
			d.Vantages = []string{}
		}
		out = append(out, d)
	}
	return out
}

func networksOf(dev db.Device, sightings []db.ListDeviceSightingsRow) []int64 {
	var nets []int64
	if dev.NetworkID != nil && *dev.NetworkID > 0 {
		nets = append(nets, *dev.NetworkID)
	}
	for _, r := range sightings {
		if r.NetworkID > 0 {
			nets = addUniqueI64(nets, r.NetworkID)
		}
	}
	if len(nets) > maxNetworks {
		nets = nets[:maxNetworks]
	}
	return nets
}

func currentAlive(addrs []*addrAgg, currentIP string) bool {
	for _, a := range addrs {
		if a.ip == currentIP {
			return a.alive
		}
	}
	return false
}

func hasLocalBit(mac string) bool {
	mac = strings.ToLower(strings.TrimSpace(mac))
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.Split(mac, ":")
	if len(parts) < 1 || len(parts[0]) != 2 {
		return false
	}
	v, err := strconv.ParseUint(parts[0], 16, 8)
	return err == nil && v&0x02 != 0
}

func addUniqueStr(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func addUniqueI64(list []int64, v int64) []int64 {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func jsonStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func macOr(mac, fallback string) string {
	if mac == "" {
		return fallback
	}
	return mac
}
