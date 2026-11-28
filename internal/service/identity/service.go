// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not accommodate;
// see LICENSE-COMMERCIAL.md.

// Package identity builds a read-only, explainable identity review model from
// facts the scan/report pipelines already persist. It never mutates devices and
// never auto-merges rows: IP/OUI alone are insufficient, and every suggestion
// carries its evidence and counter-evidence.
package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/metrics"
)

const (
	staleIdentityWindow = 7 * 24 * time.Hour
	maxCandidateLimit   = 500
)

var (
	ErrDeviceNotFound = errors.New("device not found")
	ErrInvalidFilter  = errors.New("invalid identity filter")
)

// Service computes identity projections and candidate pairs.
type Service struct {
	db  *sql.DB
	now func() time.Time
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db, now: time.Now}
}

// CandidateFilter controls the scoped review query. DeviceIDs anchors the
// result to pairs involving those devices; the comparison inventory remains the
// full scoped active set so a match on another page is not hidden.
type CandidateFilter struct {
	Limit           int
	Offset          int
	MinConfidence   domain.IdentityConfidence
	NetworkID       *int64
	DeviceIDs       []int64
	IncludeArchived bool
}

// Candidates loads the scoped active inventory in batch, builds pair indexes,
// then paginates the sorted result. No per-device queries are issued.
func (s *Service) Candidates(ctx context.Context, scope domain.Scope, filter CandidateFilter) (*domain.IdentityCandidateList, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > maxCandidateLimit {
		filter.Limit = maxCandidateLimit
	}
	if filter.Offset < 0 {
		return nil, fmt.Errorf("%w: offset must be >= 0", ErrInvalidFilter)
	}
	if filter.MinConfidence != "" && !validConfidence(filter.MinConfidence) {
		return nil, fmt.Errorf("%w: unknown confidence %q", ErrInvalidFilter, filter.MinConfidence)
	}
	inventoryFilter := filter
	inventoryFilter.DeviceIDs = nil
	devices, err := s.loadDevices(ctx, scope, inventoryFilter)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		if isGlobalInventoryQuery(scope, filter) {
			refreshMetrics(domain.IdentitySummary{})
		}
		return emptyList(filter), nil
	}
	if err := s.loadCertificates(ctx, scope, inventoryFilter, devices); err != nil {
		return nil, err
	}
	if err := s.loadPresenceCounts(ctx, devices); err != nil {
		return nil, err
	}

	candidates := buildCandidates(devices)
	summary := summarize(devices, candidates)
	if isGlobalInventoryQuery(scope, filter) {
		refreshMetrics(summary)
	}

	anchors := make(map[int64]struct{}, len(filter.DeviceIDs))
	for _, id := range filter.DeviceIDs {
		anchors[id] = struct{}{}
	}
	filtered := make([]domain.IdentityCandidate, 0, len(candidates))
	for _, c := range candidates {
		if len(anchors) > 0 {
			_, a := anchors[c.DeviceA.ID]
			_, b := anchors[c.DeviceB.ID]
			if !a && !b {
				continue
			}
		}
		if filter.MinConfidence != "" && confidenceRank(c.Confidence) < confidenceRank(filter.MinConfidence) {
			continue
		}
		filtered = append(filtered, c)
	}
	total := len(filtered)
	start := filter.Offset
	if start > total {
		start = total
	}
	end := start + filter.Limit
	if end > total {
		end = total
	}
	return &domain.IdentityCandidateList{
		Candidates: filtered[start:end], Summary: summary, Total: total, Limit: filter.Limit, Offset: filter.Offset,
	}, nil
}

// DeviceIdentity returns one device (including archived rows) plus its active
// candidate matches. Scope is enforced in SQL.
func (s *Service) DeviceIdentity(ctx context.Context, deviceID int64, scope domain.Scope) (*domain.DeviceIdentity, error) {
	filter := CandidateFilter{IncludeArchived: true, DeviceIDs: []int64{deviceID}, Limit: maxCandidateLimit}
	devices, err := s.loadDevices(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, ErrDeviceNotFound
	}
	if err := s.loadCertificates(ctx, scope, filter, devices); err != nil {
		return nil, err
	}
	if err := s.loadPresenceCounts(ctx, devices); err != nil {
		return nil, err
	}
	device := devices[0]
	// Candidate generation needs the other active rows too; load the full scoped
	// inventory once, then keep pairs involving this device.
	allFilter := CandidateFilter{IncludeArchived: false, Limit: maxCandidateLimit}
	all, err := s.loadDevices(ctx, scope, allFilter)
	if err != nil {
		return nil, err
	}
	if err := s.loadCertificates(ctx, scope, allFilter, all); err != nil {
		return nil, err
	}
	if err := s.loadPresenceCounts(ctx, all); err != nil {
		return nil, err
	}
	pairs := buildCandidates(all)
	out := make([]domain.IdentityCandidate, 0)
	for _, p := range pairs {
		if p.DeviceA.ID == deviceID || p.DeviceB.ID == deviceID {
			out = append(out, p)
		}
	}
	return &domain.DeviceIdentity{Device: device, Candidates: out}, nil
}

// --- Loading --------------------------------------------------------------

const deviceSelect = `
SELECT id, device_uuid, name, type, brand, model, ip_address, mac_address,
       serial_number, network_id, status, archived_at, first_seen, last_seen,
       scan_attributes
FROM devices d
WHERE 1=1`

func (s *Service) loadDevices(ctx context.Context, scope domain.Scope, filter CandidateFilter) ([]domain.IdentityDevice, error) {
	q := deviceSelect
	args := []any{}
	if !filter.IncludeArchived {
		q += ` AND archived_at IS NULL`
	}
	if filter.NetworkID != nil {
		q += ` AND network_id = ?`
		args = append(args, *filter.NetworkID)
	}
	scopeSQL, scopeArgs := scopeClause(scope, "d")
	q += scopeSQL
	args = append(args, scopeArgs...)
	if len(filter.DeviceIDs) > 0 {
		q += ` AND id IN (` + placeholders(len(filter.DeviceIDs)) + `)`
		for _, id := range filter.DeviceIDs {
			args = append(args, id)
		}
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("identity: load devices: %w", err)
	}
	defer rows.Close()
	out := make([]domain.IdentityDevice, 0)
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate devices: %w", err)
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDevice(row rowScanner) (domain.IdentityDevice, error) {
	var d domain.IdentityDevice
	var networkID sql.NullInt64
	var archivedAt, firstSeen, lastSeen sql.NullTime
	var attrs string
	if err := row.Scan(&d.ID, &d.UUID, &d.Name, &d.Type, &d.Brand, &d.Model,
		&d.IPAddress, &d.MACAddress, &d.SerialNumber, &networkID, &d.Status,
		&archivedAt, &firstSeen, &lastSeen, &attrs); err != nil {
		return d, fmt.Errorf("identity: scan device: %w", err)
	}
	if networkID.Valid {
		id := networkID.Int64
		d.NetworkID = &id
	}
	if archivedAt.Valid {
		t := archivedAt.Time
		d.ArchivedAt = &t
	}
	if firstSeen.Valid {
		t := firstSeen.Time
		d.FirstSeen = &t
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		d.LastSeen = &t
	}
	parsed, _ := domain.UnmarshalScanAttributes(attrs)
	d.Hostname = strings.TrimSpace(parsed.Hostname)
	d.Aliases = parseMACAliases(attrs)
	return d, nil
}

func (s *Service) loadCertificates(ctx context.Context, scope domain.Scope, filter CandidateFilter, devices []domain.IdentityDevice) error {
	byUUID := make(map[string]*domain.IdentityDevice, len(devices))
	for i := range devices {
		byUUID[devices[i].UUID] = &devices[i]
	}
	q := `
SELECT h.device_uuid, h.fingerprint_sha256, h.updated_at
FROM host_tls_certs h
JOIN devices d ON d.device_uuid = h.device_uuid
WHERE h.device_uuid != '' AND h.fingerprint_sha256 != '' AND h.cert_index = 0`
	args := []any{}
	if !filter.IncludeArchived {
		q += ` AND d.archived_at IS NULL`
	}
	if filter.NetworkID != nil {
		q += ` AND d.network_id = ?`
		args = append(args, *filter.NetworkID)
	}
	scopeSQL, scopeArgs := scopeClause(scope, "d")
	q += scopeSQL
	args = append(args, scopeArgs...)
	if len(filter.DeviceIDs) > 0 {
		q += ` AND d.id IN (` + placeholders(len(filter.DeviceIDs)) + `)`
		for _, id := range filter.DeviceIDs {
			args = append(args, id)
		}
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("identity: load certificates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var uuid, fingerprint string
		var updatedAt time.Time
		if err := rows.Scan(&uuid, &fingerprint, &updatedAt); err != nil {
			return fmt.Errorf("identity: scan certificate: %w", err)
		}
		d := byUUID[uuid]
		if d == nil {
			continue
		}
		fingerprint = normalizeCertificateFingerprint(fingerprint)
		if fingerprint == "" {
			continue
		}
		if !contains(d.CertFingerprints, fingerprint) {
			d.CertFingerprints = append(d.CertFingerprints, fingerprint)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("identity: iterate certificates: %w", err)
	}
	return nil
}

func (s *Service) loadPresenceCounts(ctx context.Context, devices []domain.IdentityDevice) error {
	if len(devices) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(devices))
	for _, d := range devices {
		ids = append(ids, d.ID)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT device_id, COUNT(*) FROM device_network_presence WHERE device_id IN (`+placeholders(len(ids))+`) GROUP BY device_id`, idsToAny(ids)...)
	if err != nil {
		return fmt.Errorf("identity: load presence counts: %w", err)
	}
	defer rows.Close()
	counts := make(map[int64]int, len(devices))
	for rows.Next() {
		var id int64
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return fmt.Errorf("identity: scan presence count: %w", err)
		}
		counts[id] = count
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("identity: iterate presence counts: %w", err)
	}
	now := s.now()
	for i := range devices {
		devices[i].MultiHomed = counts[devices[i].ID] > 1
		devices[i].Stale = devices[i].LastSeen == nil || now.Sub(*devices[i].LastSeen) > staleIdentityWindow
		devices[i].EvidenceCoverage = evidenceCoverage(devices[i])
	}
	return nil
}

// --- Candidate construction ----------------------------------------------

type pairAccumulator struct {
	candidate domain.IdentityCandidate
	signals   map[domain.IdentitySignal]bool
}

func buildCandidates(devices []domain.IdentityDevice) []domain.IdentityCandidate {
	byID := make(map[int64]*domain.IdentityDevice, len(devices))
	hostnameIndex := make(map[string][]int64)
	serialIndex := make(map[string][]int64)
	certIndex := make(map[string][]int64)
	macIndex := make(map[string][]int64)
	for i := range devices {
		d := &devices[i]
		byID[d.ID] = d
		if h := normalizeHostname(d.Hostname); h != "" {
			hostnameIndex[h] = append(hostnameIndex[h], d.ID)
		}
		if serial := normalizeSerial(d.SerialNumber); serial != "" {
			serialIndex[serial] = append(serialIndex[serial], d.ID)
		}
		for _, fp := range d.CertFingerprints {
			if fp = normalizeCertificateFingerprint(fp); fp != "" {
				certIndex[fp] = append(certIndex[fp], d.ID)
			}
		}
		if mac := normalizeMAC(d.MACAddress); mac != "" {
			macIndex[mac] = append(macIndex[mac], d.ID)
		}
		for _, alias := range d.Aliases {
			if mac := normalizeMAC(alias); mac != "" {
				macIndex[mac] = append(macIndex[mac], d.ID)
			}
		}
	}

	pairs := make(map[string]*pairAccumulator)
	addIndex := func(index map[string][]int64, signal domain.IdentitySignal, source string) {
		for value, ids := range index {
			if len(ids) < 2 {
				continue
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for i := 0; i < len(ids)-1; i++ {
				for j := i + 1; j < len(ids); j++ {
					if ids[i] == ids[j] {
						continue
					}
					a, b := byID[ids[i]], byID[ids[j]]
					if a == nil || b == nil || a.ArchivedAt != nil || b.ArchivedAt != nil {
						continue
					}
					key := pairKey(a.ID, b.ID)
					acc := pairs[key]
					if acc == nil {
						acc = &pairAccumulator{
							candidate: domain.IdentityCandidate{ID: key, DeviceA: *a, DeviceB: *b},
							signals:   make(map[domain.IdentitySignal]bool),
						}
						pairs[key] = acc
					}
					if !acc.signals[signal] {
						acc.signals[signal] = true
						acc.candidate.Signals = append(acc.candidate.Signals, signal)
					}
					detail := signalDetail(signal, a, b, value)
					acc.candidate.Evidence = append(acc.candidate.Evidence, domain.IdentityEvidence{
						Signal: signal, Source: source, Detail: detail,
						ObservedAt: latestSeen(a.LastSeen, b.LastSeen),
					})
				}
			}
		}
	}
	addIndex(hostnameIndex, domain.IdentitySignalHostname, "devices.scan_hostname")
	addIndex(serialIndex, domain.IdentitySignalSerial, "devices.serial_number")
	addIndex(certIndex, domain.IdentitySignalCertificate, "host_tls_certs.fingerprint_sha256")
	addIndex(macIndex, domain.IdentitySignalMACAlias, "devices.mac_address/scan_attributes.mac_aliases")

	out := make([]domain.IdentityCandidate, 0, len(pairs))
	for _, acc := range pairs {
		finalizeCandidate(&acc.candidate)
		out = append(out, acc.candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func finalizeCandidate(c *domain.IdentityCandidate) {
	sort.Slice(c.Signals, func(i, j int) bool { return c.Signals[i] < c.Signals[j] })
	c.Kind = string(c.Signals[0])
	if len(c.Signals) > 1 {
		c.Kind = "combined"
	}
	c.Score = 0
	for _, signal := range c.Signals {
		switch signal {
		case domain.IdentitySignalSerial:
			c.Score += 80
		case domain.IdentitySignalMACAlias:
			c.Score += 70
		case domain.IdentitySignalCertificate:
			c.Score += 50
		case domain.IdentitySignalHostname:
			c.Score += 35
		}
	}
	if len(c.Signals) > 1 {
		c.Score += 10
	}
	c.TemporalOverlap = temporalOverlap(c.DeviceA, c.DeviceB)
	if c.TemporalOverlap {
		c.Score += 5
	}
	if sameText(c.DeviceA.Brand, c.DeviceB.Brand) || sameText(c.DeviceA.Model, c.DeviceB.Model) {
		c.Score += 5
	}
	serialA, serialB := normalizeSerial(c.DeviceA.SerialNumber), normalizeSerial(c.DeviceB.SerialNumber)
	if serialA != "" && serialB != "" && serialA != serialB {
		c.Score -= 40
		c.CounterEvidence = append(c.CounterEvidence, "both rows carry different non-empty serial numbers")
	}
	if !c.TemporalOverlap && activityWindowKnown(c.DeviceA) && activityWindowKnown(c.DeviceB) {
		c.Score -= 15
		c.CounterEvidence = append(c.CounterEvidence, "recorded activity windows do not overlap")
	}
	if c.Score < 0 {
		c.Score = 0
	}
	if c.Score > 99 {
		c.Score = 99
	}
	switch {
	case c.Score >= 80:
		c.Confidence = domain.IdentityConfidenceHigh
	case c.Score >= 55:
		c.Confidence = domain.IdentityConfidenceMedium
	default:
		c.Confidence = domain.IdentityConfidenceLow
	}
}

func signalDetail(signal domain.IdentitySignal, a, b *domain.IdentityDevice, value string) string {
	switch signal {
	case domain.IdentitySignalHostname:
		return fmt.Sprintf("normalized hostname %q shared by #%d and #%d", value, a.ID, b.ID)
	case domain.IdentitySignalSerial:
		return fmt.Sprintf("serial %q shared by #%d and #%d", value, a.ID, b.ID)
	case domain.IdentitySignalCertificate:
		return fmt.Sprintf("leaf TLS certificate fingerprint %s shared by #%d and #%d", value, a.ID, b.ID)
	case domain.IdentitySignalMACAlias:
		return fmt.Sprintf("MAC %s links #%d and #%d through current/alias identity fields", value, a.ID, b.ID)
	default:
		return value
	}
}

// --- Summary/metrics ------------------------------------------------------

func summarize(devices []domain.IdentityDevice, candidates []domain.IdentityCandidate) domain.IdentitySummary {
	s := domain.IdentitySummary{TotalDevices: int64(len(devices)), CandidateCount: int64(len(candidates))}
	var coverage float64
	unknown, stale := 0, 0
	for _, d := range devices {
		coverage += d.EvidenceCoverage
		if strings.EqualFold(d.Type, "other") || strings.TrimSpace(d.Type) == "" {
			unknown++
		}
		if d.Stale {
			stale++
		}
	}
	for _, c := range candidates {
		switch c.Confidence {
		case domain.IdentityConfidenceHigh:
			s.HighCount++
		case domain.IdentityConfidenceMedium:
			s.MediumCount++
		default:
			s.LowCount++
		}
	}
	if len(devices) > 0 {
		s.UnknownRate = float64(unknown) / float64(len(devices))
		s.StaleRate = float64(stale) / float64(len(devices))
		s.EvidenceCoverage = coverage / float64(len(devices))
	}
	return s
}

func isGlobalInventoryQuery(scope domain.Scope, filter CandidateFilter) bool {
	return scope.IsGlobal() && filter.NetworkID == nil && len(filter.DeviceIDs) == 0
}

func refreshMetrics(s domain.IdentitySummary) {
	metrics.MibeeIdentityCandidates.WithLabelValues("high").Set(float64(s.HighCount))
	metrics.MibeeIdentityCandidates.WithLabelValues("medium").Set(float64(s.MediumCount))
	metrics.MibeeIdentityCandidates.WithLabelValues("low").Set(float64(s.LowCount))
	metrics.MibeeIdentityUnknownRate.Set(s.UnknownRate)
	metrics.MibeeIdentityStaleRate.Set(s.StaleRate)
	metrics.MibeeIdentityEvidenceCoverage.Set(s.EvidenceCoverage)
}

// --- Helpers --------------------------------------------------------------

func emptyList(filter CandidateFilter) *domain.IdentityCandidateList {
	return &domain.IdentityCandidateList{Candidates: []domain.IdentityCandidate{}, Total: 0, Limit: filter.Limit, Offset: filter.Offset}
}

func validConfidence(c domain.IdentityConfidence) bool {
	return c == domain.IdentityConfidenceHigh || c == domain.IdentityConfidenceMedium || c == domain.IdentityConfidenceLow
}

func confidenceRank(c domain.IdentityConfidence) int {
	switch c {
	case domain.IdentityConfidenceHigh:
		return 3
	case domain.IdentityConfidenceMedium:
		return 2
	default:
		return 1
	}
}

func normalizeHostname(hostname string) string {
	raw := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(hostname, ".")))
	if raw == "" || net.ParseIP(raw) != nil {
		return ""
	}
	h := raw
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	if len(h) < 3 || strings.ContainsAny(h, " /\\") || !hasASCIILetter(h) {
		return ""
	}
	switch h {
	case "localhost", "unknown", "device", "router", "switch", "camera", "server", "nas":
		return ""
	default:
		return h
	}
}

func hasASCIILetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
			return true
		}
	}
	return false
}

func normalizeSerial(serial string) string {
	s := strings.ToUpper(strings.TrimSpace(serial))
	switch s {
	case "", "UNKNOWN", "N/A", "NA", "NONE", "0", "DEFAULT":
		return ""
	default:
		return s
	}
}

func normalizeMAC(mac string) string {
	parsed, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.String())
}

func normalizeCertificateFingerprint(fingerprint string) string {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || len(decoded) != sha256.Size {
		return ""
	}
	return fingerprint
}

func parseMACAliases(attrs string) []string {
	var raw map[string]any
	if json.Unmarshal([]byte(attrs), &raw) != nil {
		return []string{}
	}
	values, _ := raw["mac_aliases"].([]any)
	out := make([]string, 0, len(values))
	for _, v := range values {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func evidenceCoverage(d domain.IdentityDevice) float64 {
	present := 0
	if d.MACAddress != "" {
		present++
	}
	if normalizeHostname(d.Hostname) != "" {
		present++
	}
	if normalizeSerial(d.SerialNumber) != "" {
		present++
	}
	if d.Brand != "" || d.Model != "" {
		present++
	}
	if len(d.CertFingerprints) > 0 {
		present++
	}
	if len(d.Aliases) > 0 {
		present++
	}
	return float64(present) / 6
}

func temporalOverlap(a, b domain.IdentityDevice) bool {
	if !activityWindowKnown(a) || !activityWindowKnown(b) {
		return false
	}
	aStart, bStart := a.FirstSeen, b.FirstSeen
	if aStart == nil {
		aStart = a.LastSeen
	}
	if bStart == nil {
		bStart = b.LastSeen
	}
	return !aStart.After(*b.LastSeen) && !bStart.After(*a.LastSeen)
}

func activityWindowKnown(d domain.IdentityDevice) bool {
	return d.FirstSeen != nil || d.LastSeen != nil
}

func latestSeen(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.After(*b) {
		return a
	}
	return b
}

func sameText(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && b != "" && strings.EqualFold(a, b)
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func pairKey(a, b int64) string {
	if a > b {
		a, b = b, a
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", a, b)))
	return hex.EncodeToString(sum[:6])
}

func scopeClause(scope domain.Scope, alias string) (string, []any) {
	if scope.IsGlobal() {
		return "", nil
	}
	if len(scope.NetworkIDs) == 0 {
		return " AND 0=1", nil
	}
	return " AND " + alias + ".network_id IN (" + placeholders(len(scope.NetworkIDs)) + ")", idsToAny(scope.NetworkIDs)
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func idsToAny(ids []int64) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}
