// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
)

// openEpisodeWorld builds the minimal main-DB slice the detector reads:
// probe_targets + probe_results, plus the probe_ext side store.
func openEpisodeWorld(t *testing.T) (*EpisodeService, *fakeRecorder, *sql.DB, *Store) {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for _, ddl := range []string{
		`CREATE TABLE probe_targets (
			id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, module TEXT NOT NULL,
			target TEXT NOT NULL, interval_seconds INTEGER NOT NULL DEFAULT 60,
			timeout_seconds INTEGER NOT NULL DEFAULT 10, enabled INTEGER NOT NULL DEFAULT 1,
			notes TEXT NOT NULL DEFAULT '', last_run_at TEXT NOT NULL DEFAULT '',
			last_status TEXT NOT NULL DEFAULT '', last_latency_ms REAL NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, vantage TEXT NOT NULL DEFAULT 'center',
			options TEXT NOT NULL DEFAULT '', device_id INTEGER, source TEXT NOT NULL DEFAULT 'manual')`,
		`CREATE TABLE probe_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL,
			status TEXT NOT NULL, latency_ms REAL NOT NULL DEFAULT 0, status_code INTEGER NOT NULL DEFAULT 0,
			error_message TEXT NOT NULL DEFAULT '', tls_version TEXT NOT NULL DEFAULT '',
			cert_not_after TEXT NOT NULL DEFAULT '', cert_trusted INTEGER NOT NULL DEFAULT -1,
			checked_at TEXT NOT NULL DEFAULT '', vantage TEXT NOT NULL DEFAULT 'center')`,
	} {
		if _, err := conn.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	store := openTestStore(t)
	rec := &fakeRecorder{}
	cfg := config.QualityEpisodeConfig{
		LatencyRatio: 2.0, LatencyMinDeltaMs: 50, OkRateDrop: 0.3, MinWindows: 2,
	}
	svc := NewEpisodeService(store, sqldb.New(conn), conn, cfg, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return svc, rec, conn, store
}

// fakeRecorder collects events for assertions.
type fakeRecorder struct {
	mu     sync.Mutex
	events []changedetect.ChangeEvent
}

func (f *fakeRecorder) Record(_ context.Context, ev changedetect.ChangeEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
}

func (f *fakeRecorder) snapshot() []changedetect.ChangeEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]changedetect.ChangeEvent(nil), f.events...)
}

// seedTrack fills one track's baseline (past 3h, one sample every 6 minutes
// so the 72h bucket crosses episodeMinBaseline) and optionally its degraded
// windows (last n windows at latency/degraded latency).
func seedTrack(t *testing.T, conn *sql.DB, targetID int64, vantage string, degradedWindows int, degLatency float64, degOk bool) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	// Baseline: 40 samples over the past 4 hours.
	for i := 1; i <= 40; i++ {
		at := now.Add(-time.Duration(i*6) * time.Minute)
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO probe_results (target_id, status, latency_ms, checked_at, vantage) VALUES (?, 'success', 100, ?, ?)`,
			targetID, at.Format(time.RFC3339), vantage); err != nil {
			t.Fatal(err)
		}
	}
	// Degraded windows: the detector judges the last minWindows COMPLETE
	// 15-minute windows (the in-flight window is dropped), so seeding starts
	// one window earlier. Eight samples per window (~90s apart) keep the
	// ok-rate signal dense enough to survive the 6-minute baseline cadence.
	for i := 0; i < degradedWindows; i++ {
		winStart := now.Add(-time.Duration(i+2) * episodeWindow)
		for j := 0; j < 8; j++ {
			at := winStart.Add(time.Duration(j)*90*time.Second + 30*time.Second)
			status := "success"
			lat := degLatency
			if !degOk {
				status = "timeout"
				lat = 0
			}
			if _, err := conn.ExecContext(ctx,
				`INSERT INTO probe_results (target_id, status, latency_ms, error_message, checked_at, vantage) VALUES (?, ?, ?, ?, ?, ?)`,
				targetID, status, lat, map[bool]string{true: "", false: "i/o timeout"}[status == "success"], at.Format(time.RFC3339), vantage); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func insertEpisodeTarget(t *testing.T, conn *sql.DB, id int64, name, source string) {
	t.Helper()
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO probe_targets (id, name, module, target, source, vantage) VALUES (?, ?, 'http', ?, ?, 'all')`,
		id, name, "http://"+name, source); err != nil {
		t.Fatal(err)
	}
}

// TestEpisodeNetworkLevelConfirmedAndGated: two quality tracks on one vantage
// degrade together → a network episode opens. Without a same-window egress
// change and with the attribution gate on, it stays recorded-only (no event).
func TestEpisodeNetworkLevelConfirmedAndGated(t *testing.T) {
	svc, rec, conn, store := openEpisodeWorld(t)
	insertEpisodeTarget(t, conn, 1, "quality-a", "system")
	insertEpisodeTarget(t, conn, 2, "quality-b", "system")
	seedTrack(t, conn, 1, "center", 2, 400, true)
	seedTrack(t, conn, 2, "center", 2, 400, true)

	if err := svc.Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}
	active, err := store.ListActiveEpisodes(context.Background())
	if err != nil || len(active) != 1 {
		t.Fatalf("active=%d err=%v, want 1 network episode", len(active), err)
	}
	ep := active[0]
	if ep.Kind != EpisodeKindNetwork || ep.VantageGroup != "center" {
		t.Fatalf("episode = %+v", ep)
	}
	if len(ep.MetricDegraded) != 2 {
		t.Fatalf("metrics = %+v", ep.MetricDegraded)
	}
	if ep.Notified {
		t.Fatal("attribution gate must keep an unattributed episode recorded-only")
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("no event may fire without attribution, got %+v", got)
	}

	// Round 2 (still degraded): continuation bumps windows, still one episode.
	if err := svc.Detect(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, _ = store.ListActiveEpisodes(context.Background())
	if len(active) != 1 || active[0].Windows < 2 {
		t.Fatalf("continuation failed: %+v", active)
	}

	// Round 3 with the degradation gone (fresh good windows): resolution.
	// Overwrite the degraded samples with good ones.
	if _, err := conn.ExecContext(context.Background(),
		`UPDATE probe_results SET status='success', latency_ms=100, error_message='' WHERE latency_ms >= 400`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Detect(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, _ = store.ListActiveEpisodes(context.Background())
	if len(active) != 0 {
		t.Fatalf("episode must resolve, got %+v", active)
	}
	// Recovered event only fires for episodes that notified — none here.
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("unexpected recovery events: %+v", got)
	}
}

// TestEpisodeAttributionNotifies: the same network degradation WITH a
// same-window egress identity change fires quality_degraded, and the later
// resolution fires quality_recovered (firing/resolved pair).
func TestEpisodeAttributionNotifies(t *testing.T) {
	svc, rec, conn, store := openEpisodeWorld(t)
	insertEpisodeTarget(t, conn, 1, "quality-a", "system")
	insertEpisodeTarget(t, conn, 2, "quality-b", "system")
	seedTrack(t, conn, 1, "center", 2, 400, true)
	seedTrack(t, conn, 2, "center", 2, 400, true)
	ctx := context.Background()

	// Egress identity change inside the attribution window: two adjacent
	// rounds with different public IPs.
	now := time.Now().UTC().Format(time.RFC3339)
	prev := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	if err := store.InsertEgressRound(ctx, []EgressRow{
		{Vantage: "center", RoundAt: prev, Source: "s1", Kind: "http", OK: true, IP: "93.184.216.1"},
		{Vantage: "center", RoundAt: now, Source: "s1", Kind: "http", OK: true, IP: "93.184.216.2"},
	}); err != nil {
		t.Fatal(err)
	}

	if err := svc.Detect(ctx); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ListActiveEpisodes(ctx)
	if len(active) != 1 || !active[0].Notified {
		t.Fatalf("attributed episode must notify: %+v", active)
	}
	events := rec.snapshot()
	if len(events) != 1 || events[0].ChangeType != changedetect.ChangeTypeQualityDegraded {
		t.Fatalf("events = %+v", events)
	}
	if events[0].EntityType != changedetect.EntityTypeProbeQuality {
		t.Fatalf("entity type = %q", events[0].EntityType)
	}
	if len(active[0].Attribution) == 0 {
		t.Fatal("attribution must be recorded on the episode row")
	}

	// Resolution round: everything good again → quality_recovered.
	if _, err := conn.ExecContext(ctx,
		`UPDATE probe_results SET status='success', latency_ms=100, error_message='' WHERE latency_ms >= 400`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Detect(ctx); err != nil {
		t.Fatal(err)
	}
	events = rec.snapshot()
	if len(events) != 2 || events[1].ChangeType != changedetect.ChangeTypeQualityRecovered {
		t.Fatalf("recovery must pair: %+v", events)
	}
}

// TestEpisodePathLevelTwoTargetsOneVantage: two external targets sharing a
// destination /24 (per their latest path samples) degrade from the same
// (only) vantage → a path episode; a single degraded target alone does not
// confirm (the #720 reverse case).
func TestEpisodePathLevelTwoTargetsOneVantage(t *testing.T) {
	svc, rec, conn, store := openEpisodeWorld(t)
	insertEpisodeTarget(t, conn, 11, "site-a", "manual")
	insertEpisodeTarget(t, conn, 12, "site-b", "manual")
	insertEpisodeTarget(t, conn, 13, "site-c", "manual")
	ctx := context.Background()
	// Destination groups: a+b share 203.0.113.0/24 (documentation range is
	// fine here - only the grouping matters), c is alone.
	for id, ip := range map[int64]string{11: "203.0.113.10", 12: "203.0.113.20", 13: "198.51.100.5"} {
		if _, err := store.InsertPathSample(ctx, PathSample{
			TargetID: id, TargetName: "x", Vantage: "center", ResolvedIP: ip,
			Method: "tcp", EndState: "reached", TracedAt: time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			t.Fatal(err)
		}
	}
	seedTrack(t, conn, 11, "center", 2, 400, true)
	seedTrack(t, conn, 12, "center", 2, 400, true)
	// Reverse case: only one target of a group degrades → no episode for it.
	seedTrack(t, conn, 13, "center", 2, 400, true)

	if err := svc.Detect(ctx); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ListActiveEpisodes(ctx)
	if len(active) != 1 {
		t.Fatalf("active=%d, want exactly the shared-destination path episode", len(active))
	}
	ep := active[0]
	if ep.Kind != EpisodeKindPath || ep.TargetGroup != "203.0.113.0/24" {
		t.Fatalf("episode = %+v", ep)
	}
	if len(ep.MetricDegraded) != 2 {
		t.Fatalf("metrics = %+v", ep.MetricDegraded)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("no attribution present → recorded only, got %+v", got)
	}
}

// TestEpisodeSingleTrackNoConfirmation: one degraded quality track on its
// own never opens an episode (cross-confirmation is the whole point).
func TestEpisodeSingleTrackNoConfirmation(t *testing.T) {
	svc, rec, conn, store := openEpisodeWorld(t)
	insertEpisodeTarget(t, conn, 1, "quality-a", "system")
	seedTrack(t, conn, 1, "center", 2, 400, true)

	if err := svc.Detect(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ListActiveEpisodes(context.Background())
	if len(active) != 0 {
		t.Fatalf("single-track degradation must not confirm: %+v", active)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatal("no events either")
	}
}

// TestEpisodeOkRateDropOnly: a success-rate collapse without latency
// degradation still confirms (both thresholds are independent).
func TestEpisodeOkRateDropOnly(t *testing.T) {
	svc, _, conn, store := openEpisodeWorld(t)
	insertEpisodeTarget(t, conn, 1, "quality-a", "system")
	insertEpisodeTarget(t, conn, 2, "quality-b", "system")
	seedTrack(t, conn, 1, "center", 2, 100, false) // half timeout, latency unchanged
	seedTrack(t, conn, 2, "center", 2, 100, false)

	if err := svc.Detect(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ListActiveEpisodes(context.Background())
	if len(active) != 1 {
		t.Fatalf("ok-rate drop must confirm: %+v", active)
	}
	if active[0].MetricDegraded[0].Reason != "ok_rate" {
		t.Fatalf("reason = %+v", active[0].MetricDegraded[0])
	}
}

// TestDegradeMetricPure pins the two thresholds and their floor semantics.
func TestDegradeMetricPure(t *testing.T) {
	cfg := config.QualityEpisodeConfig{LatencyRatio: 2.0, LatencyMinDeltaMs: 50, OkRateDrop: 0.3}
	bl := &baseline{p50: 100, okRate: 1.0, n: 100}
	k := trackKey{1, "center"}

	// Clean window: not degraded.
	st := &windowStats{samples: 10, ok: 10, latencies: []float64{95, 100, 105}}
	if m := degradeMetric(k, "t", st, bl, cfg); m != nil {
		t.Fatalf("clean window degraded: %+v", m)
	}
	// Latency 3x: degraded (latency reason).
	st = &windowStats{samples: 10, ok: 10, latencies: []float64{290, 300, 310}}
	if m := degradeMetric(k, "t", st, bl, cfg); m == nil || m.Reason != "latency" {
		t.Fatalf("3x latency: %+v", m)
	}
	// Small baseline floor: 3ms base cannot double into noise (needs +50ms).
	blTiny := &baseline{p50: 3, okRate: 1.0, n: 100}
	st = &windowStats{samples: 10, ok: 10, latencies: []float64{10, 11, 12}}
	if m := degradeMetric(k, "t", st, blTiny, cfg); m != nil {
		t.Fatalf("tiny-baseline noise degraded: %+v", m)
	}
	st = &windowStats{samples: 10, ok: 10, latencies: []float64{60, 61, 62}}
	if m := degradeMetric(k, "t", st, blTiny, cfg); m == nil {
		t.Fatal("tiny baseline +57ms must degrade (min-delta floor)")
	}
	// Ok-rate collapse: degraded (ok_rate reason), latency unchanged.
	st = &windowStats{samples: 10, ok: 5, latencies: []float64{95, 100, 105}}
	if m := degradeMetric(k, "t", st, bl, cfg); m == nil || m.Reason != "ok_rate" {
		t.Fatalf("ok-rate collapse: %+v", m)
	}
	// Both: reason=both.
	st = &windowStats{samples: 10, ok: 0}
	if m := degradeMetric(k, "t", st, bl, cfg); m == nil || m.Reason != "ok_rate" {
		t.Fatalf("total outage: %+v", m)
	}
}

// TestSlash24AndMedian: pure helpers.
func TestSlash24AndMedian(t *testing.T) {
	if got := slash24("203.0.113.20"); got != "203.0.113.0/24" {
		t.Fatalf("slash24 = %q", got)
	}
	if got := median([]float64{5, 1, 9}); got != 5 {
		t.Fatalf("median = %v", got)
	}
	if got := median(nil); got != 0 {
		t.Fatalf("median(nil) = %v", got)
	}
}

// TestEpisodeStoreRoundtrip: insert → active list → resolve → history list.
func TestEpisodeStoreRoundtrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	id, err := store.InsertEpisode(ctx, QualityEpisode{
		Kind: EpisodeKindNetwork, VantageGroup: "center", TargetGroup: "",
		StartedAt: "2026-11-08T08:00:00Z", LastSeenAt: "2026-11-08T08:30:00Z", Windows: 3,
		MetricDegraded: []EpisodeMetric{{TargetID: 1, Name: "a", Vantage: "center", P50Ms: 400, BaseP50Ms: 100, Reason: "latency"}},
		Attribution:    []EpisodeAttribution{{Kind: "egress_change", Detail: "x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.ListActiveEpisodes(ctx)
	if err != nil || len(active) != 1 {
		t.Fatalf("active=%d err=%v", len(active), err)
	}
	if active[0].ID != id || len(active[0].MetricDegraded) != 1 || len(active[0].Attribution) != 1 {
		t.Fatalf("row = %+v", active[0])
	}
	if err := store.ResolveEpisode(ctx, id, "2026-11-08T09:00:00Z"); err != nil {
		t.Fatal(err)
	}
	active, _ = store.ListActiveEpisodes(ctx)
	if len(active) != 0 {
		t.Fatalf("resolved episode still active: %+v", active)
	}
	hist, err := store.ListEpisodesSince(ctx, "2026-11-08T00:00:00Z", 10)
	if err != nil || len(hist) != 1 || hist[0].ResolvedAt == "" {
		t.Fatalf("history=%d err=%v", len(hist), err)
	}
}

// TestEgressChangedBetween: adjacent rounds with differing public-IP sets are
// detected; a stable sequence is not.
func TestEgressChangedBetween(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	// Stable sequence.
	_ = store.InsertEgressRound(ctx, []EgressRow{
		{Vantage: "center", RoundAt: "2026-11-08T07:00:00Z", Source: "s", Kind: "http", OK: true, IP: "93.184.216.1"},
		{Vantage: "center", RoundAt: "2026-11-08T07:05:00Z", Source: "s", Kind: "http", OK: true, IP: "93.184.216.1"},
	})
	if changed, _ := store.EgressChangedBetween(ctx, "center", "2026-11-08T06:30:00Z", "2026-11-08T07:30:00Z"); changed {
		t.Fatal("stable sequence must not report a change")
	}
	// Change: new IP appears.
	_ = store.InsertEgressRound(ctx, []EgressRow{
		{Vantage: "center", RoundAt: "2026-11-08T07:10:00Z", Source: "s", Kind: "http", OK: true, IP: "93.184.216.9"},
	})
	changed, at := store.EgressChangedBetween(ctx, "center", "2026-11-08T06:30:00Z", "2026-11-08T07:30:00Z")
	if !changed || at != "2026-11-08T07:10:00Z" {
		t.Fatalf("changed=%v at=%q", changed, at)
	}
}

// TestPathChangedBetween: adjacent samples with differing hop JSON count as
// changes for the involved targets.
func TestPathChangedBetween(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	mk := func(id int64, at, hops string) {
		if _, err := store.Conn().ExecContext(ctx,
			`INSERT INTO path_samples (target_id, vantage, method, end_state, hops, traced_at) VALUES (?, 'center', 'tcp', 'reached', ?, ?)`,
			id, hops, at); err != nil {
			t.Fatal(err)
		}
	}
	mk(7, "2026-11-08T07:00:00Z", `[{"ttl":1,"ip":"1.1.1.1"}]`)
	mk(7, "2026-11-08T07:20:00Z", `[{"ttl":1,"ip":"2.2.2.2"}]`)
	mk(8, "2026-11-08T07:00:00Z", `[{"ttl":1,"ip":"1.1.1.1"}]`)
	mk(8, "2026-11-08T07:20:00Z", `[{"ttl":1,"ip":"1.1.1.1"}]`)
	if n := store.PathChangedBetween(ctx, []int64{7, 8}, "center", "2026-11-08T06:30:00Z", "2026-11-08T07:30:00Z"); n != 1 {
		t.Fatalf("changed targets = %d, want 1", n)
	}
}

// TestRequiresAttributionDefault: the pointer semantics — absent key means
// true (#716 ruling), explicit false is honored.
func TestRequiresAttributionDefault(t *testing.T) {
	var zero config.QualityEpisodeConfig
	if !zero.RequiresAttribution() {
		t.Fatal("absent key must default to true")
	}
	f := false
	zero.AlertRequiresAttribution = &f
	if zero.RequiresAttribution() {
		t.Fatal("explicit false must win")
	}
	tr := true
	zero.AlertRequiresAttribution = &tr
	if !zero.RequiresAttribution() {
		t.Fatal("explicit true")
	}
	// DetectorEnabled: nil follows quality.enabled; explicit wins.
	if !zero.DetectorEnabled(true) || zero.DetectorEnabled(false) {
		t.Fatal("nil follows quality.enabled")
	}
	off := false
	zero.Enabled = &off
	if zero.DetectorEnabled(true) {
		t.Fatal("explicit off wins")
	}
}

// TestEpisodeErrorKinds: the error-text classifier.
func TestEpisodeErrorKinds(t *testing.T) {
	cases := map[string]string{
		"i/o timeout":           "timeout",
		"dns: i/o timeout":      "dns",
		"NXDOMAIN no such host": "dns",
		"connection refused":    "connect",
		"tls handshake error":   "tls",
		"weird failure":         "other",
	}
	for msg, want := range cases {
		if got := errorKind(msg); got != want {
			t.Errorf("errorKind(%q) = %q, want %q", msg, got, want)
		}
	}
}

// silence unused-helper warnings in non-test builds of the fmt import when
// tests are the only consumer.
var _ = fmt.Sprintf

// TestEpisodePeerEgressAttribution: when another vantage's tracks collapse
// in the same window (below 50% ok, not necessarily confirmed), the episode
// gains the peer_egress_degraded attribution (destination-side hint) — and
// that attribution is enough to let the episode notify.
func TestEpisodePeerEgressAttribution(t *testing.T) {
	svc, rec, conn, store := openEpisodeWorld(t)
	insertEpisodeTarget(t, conn, 1, "quality-a", "system")
	insertEpisodeTarget(t, conn, 2, "quality-b", "system")
	seedTrack(t, conn, 1, "center", 2, 400, true)
	seedTrack(t, conn, 2, "center", 2, 400, true)
	// The peer vantage collapses (all timeouts, recent windows).
	seedTrack(t, conn, 1, "agent:peer", 2, 0, false)

	if err := svc.Detect(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ListActiveEpisodes(context.Background())
	if len(active) != 1 {
		t.Fatalf("active=%d", len(active))
	}
	var hasPeer bool
	for _, a := range active[0].Attribution {
		if a.Kind == "peer_egress_degraded" {
			hasPeer = true
		}
	}
	if !hasPeer {
		t.Fatalf("peer attribution missing: %+v", active[0].Attribution)
	}
	if !active[0].Notified {
		t.Fatal("peer attribution satisfies the gate → must notify")
	}
	events := rec.snapshot()
	if len(events) != 1 || events[0].ChangeType != changedetect.ChangeTypeQualityDegraded {
		t.Fatalf("events = %+v", events)
	}
}
