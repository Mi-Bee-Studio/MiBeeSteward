// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/probetarget"
)

// EpisodeKind discriminates the two confirmation shapes (#720).
const (
	EpisodeKindNetwork = "network" // one egress group, most of its quality reference points degraded
	EpisodeKindPath    = "path"    // one destination group degraded from one egress group's view
)

// The detection window is fixed at 15 minutes (issue text); the loop runs
// every 5 so an episode opens within one window of the evidence forming.
const (
	episodeWindow      = 15 * time.Minute
	episodeInterval    = 5 * time.Minute
	episodeMinSamples  = 3  // window samples before a track is judged at all
	episodeMinBaseline = 20 // baseline samples before the baseline is trusted
	attributionWindow  = 30 * time.Minute
)

// EpisodeMetric is one degraded track's before/after pair (JSON in the row).
type EpisodeMetric struct {
	TargetID   int64   `json:"target_id"`
	Name       string  `json:"name"`
	Vantage    string  `json:"vantage"`
	P50Ms      float64 `json:"p50_ms"`
	BaseP50Ms  float64 `json:"base_p50_ms"`
	OkRate     float64 `json:"ok_rate"`
	BaseOkRate float64 `json:"base_ok_rate"`
	Samples    int     `json:"samples"`
	Reason     string  `json:"reason"` // latency | ok_rate | both
}

// EpisodeAttribution is one attributed same-window change (JSON in the row).
type EpisodeAttribution struct {
	Kind   string `json:"kind"` // egress_change | path_change | peer_egress_degraded | error_shape
	Detail string `json:"detail"`
	At     string `json:"at,omitempty"`
}

// QualityEpisode is one stored episode row.
type QualityEpisode struct {
	ID              int64                `json:"id"`
	Kind            string               `json:"kind"`
	VantageGroup    string               `json:"vantage_group"`
	TargetGroup     string               `json:"target_group"`
	StartedAt       string               `json:"started_at"`
	LastSeenAt      string               `json:"last_seen_at"`
	Windows         int                  `json:"windows"`
	MetricDegraded  []EpisodeMetric      `json:"metric_degraded"`
	Attribution     []EpisodeAttribution `json:"attribution"`
	Notified        bool                 `json:"notified"`
	ResolvedAt      string               `json:"resolved_at,omitempty"`
	RecoverNotified bool                 `json:"recover_notified"`
}

// EpisodeService is the #720 detector: relative-baseline degradation with
// cross-confirmation, attribution, and the impact-only alerting rule.
type EpisodeService struct {
	store    *Store
	queries  *db.Queries
	mainDB   sqlQuerier
	recorder changedetect.ChangeRecorder
	cfg      config.QualityEpisodeConfig
	logger   *slog.Logger
}

func NewEpisodeService(store *Store, queries *db.Queries, mainDB sqlQuerier, cfg config.QualityEpisodeConfig, recorder changedetect.ChangeRecorder, logger *slog.Logger) *EpisodeService {
	if logger == nil {
		logger = slog.Default()
	}
	return &EpisodeService{store: store, queries: queries, mainDB: mainDB, recorder: recorder, cfg: cfg, logger: logger}
}

// Start launches the detector loop (5-minute cadence).
func (s *EpisodeService) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(episodeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.Detect(ctx); err != nil {
					s.logger.Warn("quality episodes: detect round failed", "error", err)
				}
			}
		}
	}()
}

// trackKey identifies one execution track.
type trackKey struct {
	TargetID int64
	Vantage  string
}

// windowStats is one track's aggregates over one 15-minute window.
type windowStats struct {
	samples   int
	ok        int
	latencies []float64
}

func (w *windowStats) p50() float64 {
	if len(w.latencies) == 0 {
		return 0
	}
	v := append([]float64(nil), w.latencies...)
	sort.Float64s(v)
	return v[len(v)/2]
}

func (w *windowStats) okRate() float64 {
	if w.samples == 0 {
		return 1
	}
	return float64(w.ok) / float64(w.samples)
}

// baseline is one track's reference (72h median, or same weekday×hour once
// seven days of history exist).
type baseline struct {
	p50    float64
	okRate float64
	n      int
}

// Detect runs one full round. It is exported so tests drive it directly.
func (s *EpisodeService) Detect(ctx context.Context) error {
	now := time.Now().UTC()
	minWindows := s.cfg.MinWindows
	if minWindows < 1 {
		minWindows = 2
	}

	// Window rows: enough history for minWindows consecutive windows (plus
	// slack for staggered schedules).
	rowsSince := now.Add(-time.Duration(minWindows+1) * episodeWindow).Add(-2 * time.Minute)
	rows, err := s.queries.ListProbeResultsSince(ctx, rowsSince.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("episodes: results since: %w", err)
	}
	targets, err := s.queries.ListProbeTargets(ctx)
	if err != nil {
		return fmt.Errorf("episodes: list targets: %w", err)
	}
	targetByID := make(map[int64]db.ProbeTarget, len(targets))
	for _, t := range targets {
		targetByID[t.ID] = t
	}

	// Slice the rows into aligned 15-minute windows per track.
	windows := sliceWindows(rows, now, minWindows)
	// The freshest full window is windows[len-1]; judge the last minWindows.
	if len(windows) < minWindows {
		return nil // not enough data yet
	}
	judged := windows[len(windows)-minWindows:]

	// Baselines for every track seen in the judged windows.
	seen := make(map[trackKey]bool)
	for _, w := range judged {
		for k := range w.tracks {
			seen[k] = true
		}
	}
	baselines, err := s.trackBaselines(ctx, seen, judged[len(judged)-1].start, now)
	if err != nil {
		return fmt.Errorf("episodes: baselines: %w", err)
	}

	// Degraded candidates: degraded in EVERY judged window.
	candidates := make(map[trackKey]*EpisodeMetric)
	for wi, w := range judged {
		for k, st := range w.tracks {
			bl, ok := baselines[k]
			if !ok || bl.n < episodeMinBaseline || st.samples < episodeMinSamples {
				continue
			}
			t, ok := targetByID[k.TargetID]
			if !ok || t.Enabled != 1 {
				continue
			}
			m := degradeMetric(k, t.Name, st, bl, s.cfg)
			if m == nil {
				continue
			}
			if wi == 0 {
				candidates[k] = m
			}
		}
		if wi > 0 {
			// Drop candidates that were NOT degraded in this window.
			for k := range candidates {
				st, ok := w.tracks[k]
				if !ok || st.samples < episodeMinSamples {
					delete(candidates, k)
					continue
				}
				bl := baselines[k]
				t := targetByID[k.TargetID]
				if degradeMetric(k, t.Name, st, bl, s.cfg) == nil {
					delete(candidates, k)
				}
			}
		}
	}

	// Confirmation groups.
	groups := s.confirmGroups(ctx, candidates, targetByID)

	// Reconcile with stored episodes.
	active, err := s.store.ListActiveEpisodes(ctx)
	if err != nil {
		return fmt.Errorf("episodes: list active: %w", err)
	}
	activeByKey := make(map[string]QualityEpisode, len(active))
	for _, e := range active {
		activeByKey[e.Kind+"|"+e.VantageGroup+"|"+e.TargetGroup] = e
	}

	nowISO := now.Format(time.RFC3339)
	for _, g := range groups {
		key := g.kind + "|" + g.vantage + "|" + g.targetGroup
		if existing, ok := activeByKey[key]; ok {
			// Continuation: bump the window counter and last-seen.
			delete(activeByKey, key) // matched; survives this round
			if err := s.store.UpdateEpisodeWindow(ctx, existing.ID, nowISO); err != nil {
				s.logger.Warn("quality episodes: update failed", "id", existing.ID, "error", err)
			}
			continue
		}
		s.openEpisode(ctx, g, nowISO)
	}
	// Whatever is left in activeByKey did NOT re-confirm: resolve it.
	for _, e := range activeByKey {
		// Resolution: the confirmation dissolved.
		if err := s.store.ResolveEpisode(ctx, e.ID, nowISO); err != nil {
			s.logger.Warn("quality episodes: resolve failed", "id", e.ID, "error", err)
			continue
		}
		if e.Notified && !e.RecoverNotified && s.recorder != nil {
			s.record(ctx, changedetect.ChangeTypeQualityRecovered, e.ID, map[string]any{
				"kind": e.Kind, "vantage_group": e.VantageGroup, "target_group": e.TargetGroup,
				"started_at": e.StartedAt, "resolved_at": nowISO,
				"duration_minutes": int(time.Since(parseRFC3339(e.StartedAt)).Minutes()),
				"metrics":          e.MetricDegraded, "attribution": e.Attribution,
			})
			if err := s.store.MarkEpisodeRecoverNotified(ctx, e.ID); err != nil {
				s.logger.Warn("quality episodes: recover flag failed", "id", e.ID, "error", err)
			}
		}
		s.logger.Info("quality episode resolved",
			"id", e.ID, "kind", e.Kind, "vantage", e.VantageGroup, "notified", e.Notified)
	}
	return nil
}

// confirmedGroup is one cross-confirmed candidate episode.
type confirmedGroup struct {
	kind        string
	vantage     string
	targetGroup string
	metrics     []*EpisodeMetric
	targetIDs   []int64
}

// confirmGroups applies the two #720 cross-confirmation shapes to the
// sustained candidates: network-level (one egress group's quality reference
// points mostly degraded) and path-level (one destination group degraded
// from enough vantages).
func (s *EpisodeService) confirmGroups(ctx context.Context, candidates map[trackKey]*EpisodeMetric, targetByID map[int64]db.ProbeTarget) []confirmedGroup {
	var groups []confirmedGroup

	// Latest resolved IP per target (destination grouping via /24).
	latestPaths, err := s.store.LatestPaths(ctx, "")
	if err != nil {
		s.logger.Warn("quality episodes: latest paths failed", "error", err)
	}
	destByID := make(map[int64]string, len(latestPaths))
	for _, p := range latestPaths {
		if p.ResolvedIP != "" {
			destByID[p.TargetID] = slash24(p.ResolvedIP)
		}
	}

	// Network-level: per vantage, quality-category reference tracks.
	byVantage := make(map[string][]trackKey)
	for k := range candidates {
		if t, ok := targetByID[k.TargetID]; ok && TargetCategoryOf(t) == probetarget.ProbeCategoryQuality {
			byVantage[k.Vantage] = append(byVantage[k.Vantage], k)
		}
	}
	networkCovered := make(map[trackKey]bool)
	for vantage, tracks := range byVantage {
		// The reference population: every enabled quality target with a
		// track for this vantage in the judged windows. Without the full
		// population we use the candidate count itself (>=2 is still
		// meaningful evidence — the matrix is small).
		sort.Slice(tracks, func(i, j int) bool { return tracks[i].TargetID < tracks[j].TargetID })
		if len(tracks) < 2 {
			continue
		}
		g := confirmedGroup{kind: EpisodeKindNetwork, vantage: vantage}
		for _, k := range tracks {
			g.metrics = append(g.metrics, candidates[k])
			g.targetIDs = append(g.targetIDs, k.TargetID)
			networkCovered[k] = true
		}
		groups = append(groups, g)
	}

	// Path-level: per (vantage, destination /24), remaining tracks.
	byDest := make(map[string][]trackKey)
	for k := range candidates {
		if networkCovered[k] {
			continue
		}
		d, ok := destByID[k.TargetID]
		if !ok {
			continue
		}
		byDest[vantageDestKey(k.Vantage, d)] = append(byDest[vantageDestKey(k.Vantage, d)], k)
	}
	for key, tracks := range byDest {
		vantage, dest := splitVantageDest(key)
		targets := map[int64]bool{}
		for _, k := range tracks {
			targets[k.TargetID] = true
		}
		if len(targets) < 2 {
			continue
		}
		// Destination groups need >=2 degraded targets from this egress
		// group's view; a multi-vantage destination additionally gets
		// cross-vantage corroboration from the sibling group rows below
		// (each watching vantage confirms independently).
		sort.Slice(tracks, func(i, j int) bool { return tracks[i].TargetID < tracks[j].TargetID })
		g := confirmedGroup{kind: EpisodeKindPath, vantage: vantage, targetGroup: dest}
		for _, k := range tracks {
			g.metrics = append(g.metrics, candidates[k])
			g.targetIDs = append(g.targetIDs, k.TargetID)
		}
		groups = append(groups, g)
	}
	return groups
}

// openEpisode attributes, persists, and (if allowed) notifies a new episode.
func (s *EpisodeService) openEpisode(ctx context.Context, g confirmedGroup, nowISO string) {
	attr := s.attribute(ctx, g, nowISO)
	metrics := make([]EpisodeMetric, 0, len(g.metrics))
	for _, m := range g.metrics {
		metrics = append(metrics, *m)
	}
	ep := QualityEpisode{
		Kind: g.kind, VantageGroup: g.vantage, TargetGroup: g.targetGroup,
		StartedAt: nowISO, LastSeenAt: nowISO, Windows: 1,
		MetricDegraded: metrics, Attribution: attr,
	}
	id, err := s.store.InsertEpisode(ctx, ep)
	if err != nil {
		s.logger.Warn("quality episodes: insert failed", "error", err)
		return
	}
	ep.ID = id
	notify := !s.cfg.RequiresAttribution() || len(attr) > 0
	if notify && s.recorder != nil {
		after := map[string]any{
			"kind": ep.Kind, "vantage_group": ep.VantageGroup, "target_group": ep.TargetGroup,
			"started_at": ep.StartedAt, "metrics": metrics, "attribution": attr,
			"reason": "relative-baseline drop confirmed by cross-evidence",
		}
		s.record(ctx, changedetect.ChangeTypeQualityDegraded, id, after)
		if err := s.store.MarkEpisodeNotified(ctx, id); err != nil {
			s.logger.Warn("quality episodes: notified flag failed", "id", id, "error", err)
		}
		ep.Notified = true
	}
	s.logger.Info("quality episode opened",
		"id", id, "kind", ep.Kind, "vantage", ep.VantageGroup, "target_group", ep.TargetGroup,
		"tracks", len(metrics), "attributed", len(attr), "notified", ep.Notified)
}

// attribute collects the same-window evidence: egress changes on the
// involved vantage, path changes on the involved targets, whether other
// egress groups degraded in the same windows, and the error-shape shift.
func (s *EpisodeService) attribute(ctx context.Context, g confirmedGroup, nowISO string) []EpisodeAttribution {
	var attr []EpisodeAttribution
	start := parseRFC3339(nowISO)
	from := start.Add(-attributionWindow).Format(time.RFC3339)
	to := start.Add(attributionWindow).Format(time.RFC3339)

	// Egress identity changes on the episode's vantage (±30min).
	if changed, at := s.store.EgressChangedBetween(ctx, g.vantage, from, to); changed {
		attr = append(attr, EpisodeAttribution{
			Kind:   "egress_change",
			Detail: "public egress identity changed within ±30min of the degradation start",
			At:     at,
		})
	}
	// Path changes on the involved targets (±30min).
	if n := s.store.PathChangedBetween(ctx, g.targetIDs, g.vantage, from, to); n > 0 {
		attr = append(attr, EpisodeAttribution{
			Kind:   "path_change",
			Detail: fmt.Sprintf("%d involved target(s) changed visible path within ±30min", n),
		})
	}
	// Other egress groups degrading at the same time: everyone degraded →
	// the far end / destination side is the likelier cause.
	if s.otherGroupsDegraded(ctx, g.vantage, start) {
		attr = append(attr, EpisodeAttribution{
			Kind:   "peer_egress_degraded",
			Detail: "other egress groups show degradation in the same window (destination-side cause likely)",
		})
	}
	// Error-shape: what the failures look like (stage hint without #717's
	// phase timers — dns/connect/timeout classification from error text).
	if shape := s.errorShape(ctx, g); shape != "" {
		attr = append(attr, EpisodeAttribution{Kind: "error_shape", Detail: shape})
	}
	return attr
}

// otherGroupsDegraded samples whether any other vantage's quality tracks
// fell below their baselines in the same window (cheap version: the same
// Detect pass already produced candidates; re-derive from the last window).
func (s *EpisodeService) otherGroupsDegraded(ctx context.Context, own string, start time.Time) bool {
	rows, err := s.queries.ListProbeResultsSince(ctx, start.Add(-2*episodeWindow).Format(time.RFC3339))
	if err != nil {
		return false
	}
	stats := make(map[trackKey]*windowStats)
	for _, r := range rows {
		k := trackKey{r.TargetID, r.Vantage}
		if stats[k] == nil {
			stats[k] = &windowStats{latencies: nil}
		}
		stats[k].samples++
		if r.Status == "success" {
			stats[k].ok++
			stats[k].latencies = append(stats[k].latencies, r.LatencyMs)
		}
	}
	for k, st := range stats {
		if k.Vantage == own || st.samples < episodeMinSamples {
			continue
		}
		if st.okRate() < 0.5 {
			return true
		}
	}
	return false
}

// errorShape summarizes the failing stage across the group's recent errors
// (raw SQL: the sqlc window query trims error_message for weight).
func (s *EpisodeService) errorShape(ctx context.Context, g confirmedGroup) string {
	cutoff := time.Now().UTC().Add(-2 * episodeWindow).Format(time.RFC3339)
	wanted := make(map[int64]bool, len(g.targetIDs))
	for _, id := range g.targetIDs {
		wanted[id] = true
	}
	kinds := map[string]int{}
	rows, err := s.mainDB.QueryContext(ctx,
		`SELECT target_id, error_message FROM probe_results
		 WHERE checked_at >= ? AND vantage = ? AND status != 'success'`, cutoff, g.vantage)
	if err != nil {
		return ""
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var msg string
		if err := rows.Scan(&id, &msg); err != nil {
			return ""
		}
		if !wanted[id] {
			continue
		}
		kinds[errorKind(msg)]++
	}
	if len(kinds) == 0 {
		return ""
	}
	top, topN := "", 0
	for k, n := range kinds {
		if n > topN {
			top, topN = k, n
		}
	}
	if topN < 2 {
		return ""
	}
	return fmt.Sprintf("dominant failure shape: %s (%d samples in the window)", top, topN)
}

func errorKind(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "dns"), strings.Contains(m, "resolve"), strings.Contains(m, "nxdomain"):
		return "dns"
	case strings.Contains(m, "timeout"):
		return "timeout"
	case strings.Contains(m, "connect"), strings.Contains(m, "refused"), strings.Contains(m, "unreachable"):
		return "connect"
	case strings.Contains(m, "tls"), strings.Contains(m, "cert"):
		return "tls"
	default:
		return "other"
	}
}

// record emits one change event (nil-recorder safe).
func (s *EpisodeService) record(ctx context.Context, changeType string, episodeID int64, after map[string]any) {
	if s.recorder == nil {
		return
	}
	s.recorder.Record(ctx, changedetect.ChangeEvent{
		ChangeType: changeType,
		EntityType: changedetect.EntityTypeProbeQuality,
		DeviceID:   episodeID,
		After:      after,
	})
}

// --- pure helpers ---------------------------------------------------------

// windowSlice is one aligned 15-minute window's per-track aggregates.
type windowSlice struct {
	start  time.Time
	tracks map[trackKey]*windowStats
}

// sliceWindows buckets rows into aligned 15-minute windows ending at now.
// The partial current window is dropped; index 0 is the oldest kept window.
func sliceWindows(rows []db.ListProbeResultsSinceRow, now time.Time, minWindows int) []windowSlice {
	total := time.Duration(minWindows+1) * episodeWindow
	nWindows := int(total/episodeWindow) + 1
	ends := make([]time.Time, nWindows)
	for i := 0; i < nWindows; i++ {
		ends[i] = now.Add(-time.Duration(i) * episodeWindow)
	}
	ws := make([]windowSlice, nWindows)
	for i := range ws {
		ws[i] = windowSlice{start: ends[i].Add(-episodeWindow), tracks: map[trackKey]*windowStats{}}
	}
	for _, r := range rows {
		ts := parseRFC3339(r.CheckedAt)
		if ts.IsZero() {
			continue
		}
		for i, end := range ends {
			start := end.Add(-episodeWindow)
			if !ts.Before(start) && ts.Before(end) {
				k := trackKey{r.TargetID, r.Vantage}
				if ws[i].tracks[k] == nil {
					ws[i].tracks[k] = &windowStats{}
				}
				ws[i].tracks[k].samples++
				if r.Status == "success" {
					ws[i].tracks[k].ok++
					ws[i].tracks[k].latencies = append(ws[i].tracks[k].latencies, r.LatencyMs)
				}
				break
			}
		}
	}
	// Drop the partial current window (index 0) and order oldest-first.
	ws = ws[1:]
	for i, j := 0, len(ws)-1; i < j; i, j = i+1, j-1 {
		ws[i], ws[j] = ws[j], ws[i]
	}
	return ws
}

// trackBaselines loads per-track baselines: 72h median until the track has
// seven days of history, then the same weekday×hour buckets.
func (s *EpisodeService) trackBaselines(ctx context.Context, tracks map[trackKey]bool, windowStart, now time.Time) (map[trackKey]*baseline, error) {
	if len(tracks) == 0 {
		return map[trackKey]*baseline{}, nil
	}
	// Raw SQL (not sqlc): the dynamic per-track filter is a runtime
	// artifact, same rationale as the networks backfill note (#686).
	ids := make(map[int64]bool, len(tracks))
	for k := range tracks {
		ids[k.TargetID] = true
	}
	query := `SELECT target_id, vantage, latency_ms, checked_at, status FROM probe_results
		WHERE checked_at >= ? AND target_id IN (SELECT value FROM json_each(?))`
	idsJSON, _ := json.Marshal(keysOf(ids))
	since7d := now.Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	rows, err := s.mainQuery(ctx, query, since7d, string(idsJSON))
	if err != nil {
		return nil, err
	}
	type acc struct {
		recentLat []float64 // 72h successes
		recentTot int
		recentOk  int
		oldest    time.Time
		sameLat   []float64 // same weekday×hour successes
		sameTot   int
		sameOk    int
	}
	accs := make(map[trackKey]*acc)
	cut72h := now.Add(-72 * time.Hour)
	wantDow := int(windowStart.Weekday())
	wantHour := windowStart.Hour()
	for r := range rows {
		k := trackKey{r.targetID, r.vantage}
		a := accs[k]
		if a == nil {
			a = &acc{}
			accs[k] = a
		}
		ts := parseRFC3339(r.checkedAt)
		if a.oldest.IsZero() || ts.Before(a.oldest) {
			a.oldest = ts
		}
		if !ts.Before(cut72h) {
			a.recentTot++
			if r.status == "success" {
				a.recentOk++
				a.recentLat = append(a.recentLat, r.latencyMs)
			}
		}
		if int(ts.Weekday()) == wantDow && ts.Hour() == wantHour {
			a.sameTot++
			if r.status == "success" {
				a.sameOk++
				a.sameLat = append(a.sameLat, r.latencyMs)
			}
		}
	}
	out := make(map[trackKey]*baseline, len(accs))
	for k, a := range accs {
		hasWeek := !a.oldest.IsZero() && now.Sub(a.oldest) >= 7*24*time.Hour
		if hasWeek && a.sameTot >= episodeMinBaseline {
			out[k] = &baseline{p50: median(a.sameLat), okRate: float64(a.sameOk) / float64(a.sameTot), n: a.sameTot}
			continue
		}
		if a.recentTot >= episodeMinBaseline {
			out[k] = &baseline{p50: median(a.recentLat), okRate: float64(a.recentOk) / float64(a.recentTot), n: a.recentTot}
		}
	}
	return out, nil
}

// degradeMetric applies the two thresholds; nil = not degraded.
func degradeMetric(k trackKey, name string, st *windowStats, bl *baseline, cfg config.QualityEpisodeConfig) *EpisodeMetric {
	latDegraded := false
	if len(st.latencies) > 0 && bl.p50 > 0 {
		p := st.p50()
		threshold := math.Max(bl.p50*cfg.LatencyRatio, bl.p50+float64(cfg.LatencyMinDeltaMs))
		latDegraded = p >= threshold
	}
	okDegraded := st.okRate() <= bl.okRate-cfg.OkRateDrop
	if !latDegraded && !okDegraded {
		return nil
	}
	reason := "both"
	switch {
	case latDegraded && !okDegraded:
		reason = "latency"
	case okDegraded && !latDegraded:
		reason = "ok_rate"
	}
	return &EpisodeMetric{
		TargetID: k.TargetID, Name: name, Vantage: k.Vantage,
		P50Ms: round3(st.p50()), BaseP50Ms: round3(bl.p50),
		OkRate: round3(st.okRate()), BaseOkRate: round3(bl.okRate),
		Samples: st.samples, Reason: reason,
	}
}

func keysOf(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}

func slash24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}

func vantageDestKey(vantage, dest string) string { return vantage + "\x00" + dest }

func splitVantageDest(key string) (string, string) {
	v, d, _ := strings.Cut(key, "\x00")
	return v, d
}

func parseRFC3339(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// TargetCategoryOf avoids the probetarget import cycle risk at call time —
// direct delegation, kept for one seam.
func TargetCategoryOf(t db.ProbeTarget) string { return probetarget.TargetCategory(t) }

// --- Store row plumbing (raw SQL, same single-conn regime) ----------------

// sqlQuerier is the read slice EpisodeService needs from the main DB
// (satisfied by *sql.DB and dbopen.BusyRetry alike).
type sqlQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type rawRow struct {
	targetID  int64
	vantage   string
	latencyMs float64
	checkedAt string
	status    string
}

func (s *EpisodeService) mainQuery(ctx context.Context, query string, args ...any) (chan rawRow, error) {
	rows, err := s.mainDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	out := make(chan rawRow, 64)
	go func() {
		defer close(out)
		defer rows.Close()
		for rows.Next() {
			var r rawRow
			if err := rows.Scan(&r.targetID, &r.vantage, &r.latencyMs, &r.checkedAt, &r.status); err != nil {
				return
			}
			out <- r
		}
	}()
	return out, nil
}

// EpisodesResponse is the GET /probe-quality/episodes payload.
type EpisodesResponse struct {
	Episodes []QualityEpisode `json:"episodes"`
}

// ListEpisodesSince serves the API surface (days window).
func (s *EpisodeService) ListEpisodesSince(ctx context.Context, sinceISO string) ([]QualityEpisode, error) {
	return s.store.ListEpisodesSince(ctx, sinceISO, 200)
}
