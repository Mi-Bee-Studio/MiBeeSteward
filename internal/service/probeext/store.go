// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package probeext is the probe extension store and recorders behind the
// egress/path portfolio (#716): the probe_ext.db side database (egress echo
// rounds + path samples) plus the center-side egress-identity rounds (#718)
// and the zero-privilege path tracer (#719).
//
// The side database follows the heartbeat.db pattern on purpose: dedicated
// SQLite file next to the main DB, additive CREATE TABLE IF NOT EXISTS DDL
// with no version stamp, so shipping this never bumps SchemaVersion and
// v0.9.x deployments upgrade by replacing the binary alone.
package probeext

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "mibee-steward/internal/dbopen" // registers the modernc sqlite driver

	"mibee-steward/internal/service/probe"
)

// extSchema is the additive DDL for probe_ext.db. checked_at/round_at/
// traced_at are RFC3339 UTC strings (the modernc time.Time serialization
// caveat, same as probe_results / heartbeat_results).
const extSchema = `
CREATE TABLE IF NOT EXISTS egress_rounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vantage TEXT NOT NULL,             -- 'center' | 'agent:{agent_id}'
    round_at TEXT NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,                -- http | stun | dns | local
    ok INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    asn TEXT NOT NULL DEFAULT '',
    as_name TEXT NOT NULL DEFAULT '',
    ms REAL NOT NULL DEFAULT 0,
    err TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_egress_rounds_vantage_time ON egress_rounds(vantage, round_at);
CREATE INDEX IF NOT EXISTS idx_egress_rounds_time ON egress_rounds(round_at);

CREATE TABLE IF NOT EXISTS path_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,        -- probe_targets.id (no FK: side DB)
    vantage TEXT NOT NULL,
    target_name TEXT NOT NULL DEFAULT '',
    resolved_ip TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL,              -- tcp | icmp
    end_state TEXT NOT NULL,           -- reached | max_ttl | error
    reached_ttl INTEGER NOT NULL DEFAULT 0,
    reply_ttl INTEGER NOT NULL DEFAULT 0, -- 0 = unknown
    visible_hops INTEGER NOT NULL DEFAULT 0,
    hops TEXT NOT NULL DEFAULT '[]',   -- JSON [{ttl,ip,ms}]
    trigger TEXT NOT NULL DEFAULT 'baseline', -- baseline | manual
    err TEXT NOT NULL DEFAULT '',
    traced_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_path_samples_target ON path_samples(target_id, vantage, traced_at DESC);
CREATE INDEX IF NOT EXISTS idx_path_samples_time ON path_samples(traced_at);

CREATE TABLE IF NOT EXISTS quality_episodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                -- network | path
    vantage_group TEXT NOT NULL,       -- one vantage token today ('center' | 'agent:{id}')
    target_group TEXT NOT NULL,        -- destination /24 for path episodes, '' for network
    started_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    windows INTEGER NOT NULL DEFAULT 1,     -- consecutive degraded windows seen
    metric_degraded TEXT NOT NULL DEFAULT '[]', -- JSON [{target_id,vantage,name,p50_ms,base_p50_ms,ok_rate,base_ok_rate,samples}]
    attribution TEXT NOT NULL DEFAULT '[]',     -- JSON [{kind,detail,at}]
    notified INTEGER NOT NULL DEFAULT 0,    -- fired quality_degraded into change_log
    resolved_at TEXT NOT NULL DEFAULT '',   -- '' = active
    recover_notified INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_quality_episodes_time ON quality_episodes(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_quality_episodes_active ON quality_episodes(resolved_at, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS probe_phases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,        -- probe_targets.id (no FK: side DB)
    module TEXT NOT NULL,              -- http | tcp | icmp
    vantage TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    resolved_ip TEXT NOT NULL DEFAULT '',
    dns_ms REAL NOT NULL DEFAULT 0,    -- 0 = stage absent (non-http modules)
    connect_ms REAL NOT NULL DEFAULT 0,
    tls_ms REAL NOT NULL DEFAULT 0,
    ttfb_ms REAL NOT NULL DEFAULT 0,
    reply_ttl INTEGER NOT NULL DEFAULT 0, -- 0 = unknown (icmp)
    latency_ms REAL NOT NULL DEFAULT 0    -- run total, denormalized so phase reads need no join
);
CREATE INDEX IF NOT EXISTS idx_probe_phases_target ON probe_phases(target_id, vantage, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_probe_phases_time ON probe_phases(checked_at);
`

// Store is the probe_ext.db handle. Single connection + WAL: writes are
// low-rate (one batch per egress round / per traced target), the only other
// readers are the API handlers and the retention sweep.
type Store struct {
	conn *sql.DB
}

// OpenStore opens (creating if needed) probe_ext.db next to the given path's
// directory, applies the additive schema, and returns the store.
func OpenStore(dbPath string) (*Store, error) {
	if dir := filepath.Dir(dbPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create probe_ext db dir: %w", err)
		}
	}
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open probe_ext db: %w", err)
	}
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("probe_ext db pragma %q: %w", p, err)
		}
	}
	if _, err := conn.Exec(extSchema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("probe_ext db schema: %w", err)
	}
	return &Store{conn: conn}, nil
}

// Close closes the underlying connection.
func (s *Store) Close() error { return s.conn.Close() }

// Conn exposes the raw connection (retention sweep).
func (s *Store) Conn() *sql.DB { return s.conn }

// EgressRow is one source result within one egress round.
type EgressRow struct {
	Vantage string
	RoundAt string
	Source  string
	Kind    string
	OK      bool
	IP      string
	ASN     string
	ASName  string
	MS      float64
	Err     string
}

// InsertEgressRound writes one round's rows in a single transaction.
func (s *Store) InsertEgressRound(ctx context.Context, rows []EgressRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO egress_rounds (vantage, round_at, source, kind, ok, ip, asn, as_name, ms, err)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx, r.Vantage, r.RoundAt, r.Source, r.Kind, boolInt(r.OK), r.IP, r.ASN, r.ASName, r.MS, r.Err); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EgressIPView aggregates one observed public IP within a window.
type EgressIPView struct {
	IP        string   `json:"ip"`
	ASN       string   `json:"asn,omitempty"`
	ASName    string   `json:"as_name,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	FirstSeen string   `json:"first_seen,omitempty"`
	LastSeen  string   `json:"last_seen,omitempty"`
	Samples   int      `json:"samples"`
}

// EgressSourceView is one source's result in the latest round.
type EgressSourceView struct {
	Source string  `json:"source"`
	Kind   string  `json:"kind"`
	OK     bool    `json:"ok"`
	IP     string  `json:"ip,omitempty"`
	MS     float64 `json:"ms"`
	Err    string  `json:"err,omitempty"`
}

// EgressVantageView is the API view of one vantage's egress state.
type EgressVantageView struct {
	Vantage      string             `json:"vantage"`
	NetworkName  string             `json:"network_name,omitempty"`
	RoundAt      string             `json:"round_at,omitempty"`
	IPs          []EgressIPView     `json:"ips"`
	Sources      []EgressSourceView `json:"sources"`
	LocalGateway string             `json:"local_gateway,omitempty"`
	LocalIface   string             `json:"local_iface,omitempty"`
}

// LatestEgress builds the per-vantage view: the latest round's per-source
// results plus each distinct IP's window stats (first/last seen, sample
// count, observing sources).
func (s *Store) LatestEgress(ctx context.Context, window time.Duration) ([]EgressVantageView, error) {
	vantages, err := s.distinctVantages(ctx, "egress_rounds")
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().Add(-window).Format(time.RFC3339)
	out := make([]EgressVantageView, 0, len(vantages))
	for _, v := range vantages {
		view := EgressVantageView{Vantage: v, IPs: []EgressIPView{}, Sources: []EgressSourceView{}}
		// Latest round: the newest round_at that has rows for this vantage.
		var roundAt string
		if err := s.conn.QueryRowContext(ctx,
			`SELECT round_at FROM egress_rounds WHERE vantage = ? ORDER BY round_at DESC LIMIT 1`, v,
		).Scan(&roundAt); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, err
		}
		view.RoundAt = roundAt
		rows, err := s.conn.QueryContext(ctx,
			`SELECT source, kind, ok, ip, ms, err FROM egress_rounds
			 WHERE vantage = ? AND round_at = ? ORDER BY source`, v, roundAt)
		if err != nil {
			return nil, err
		}
		ipSources := map[string][]string{}
		for rows.Next() {
			var sv EgressSourceView
			var ok int
			if err := rows.Scan(&sv.Source, &sv.Kind, &ok, &sv.IP, &sv.MS, &sv.Err); err != nil {
				rows.Close()
				return nil, err
			}
			sv.OK = ok == 1
			if sv.Source == "local" {
				// the synthetic local-egress row carries gateway/iface in ip/err
				view.LocalGateway = sv.IP
				view.LocalIface = sv.Err
				continue
			}
			view.Sources = append(view.Sources, sv)
			if sv.OK && sv.IP != "" {
				ipSources[sv.IP] = append(ipSources[sv.IP], sv.Source)
			}
		}
		rows.Close()
		// Window stats per distinct IP (from any round in the window).
		if len(ipSources) > 0 {
			stats, err := s.ipWindowStats(ctx, v, cutoff)
			if err != nil {
				return nil, err
			}
			for ip, srcs := range ipSources {
				st := stats[ip]
				iv := EgressIPView{IP: ip, Sources: srcs, Samples: st.samples, FirstSeen: st.first, LastSeen: st.last}
				// ASN from the latest row that has one.
				_ = s.conn.QueryRowContext(ctx,
					`SELECT asn, as_name FROM egress_rounds
					 WHERE vantage = ? AND ip = ? AND asn != '' ORDER BY round_at DESC LIMIT 1`, v, ip,
				).Scan(&iv.ASN, &iv.ASName)
				view.IPs = append(view.IPs, iv)
			}
			sortIPViews(view.IPs)
		}
		out = append(out, view)
	}
	return out, nil
}

type ipStat struct {
	samples     int
	first, last string
}

func (s *Store) ipWindowStats(ctx context.Context, vantage, cutoff string) (map[string]ipStat, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT ip, count(*), min(round_at), max(round_at) FROM egress_rounds
		 WHERE vantage = ? AND ok = 1 AND ip != '' AND round_at >= ? GROUP BY ip`, vantage, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ipStat{}
	for rows.Next() {
		var ip string
		var st ipStat
		if err := rows.Scan(&ip, &st.samples, &st.first, &st.last); err != nil {
			return nil, err
		}
		out[ip] = st
	}
	return out, rows.Err()
}

func (s *Store) distinctVantages(ctx context.Context, table string) ([]string, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT DISTINCT vantage FROM `+table+` ORDER BY vantage`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func sortIPViews(ips []EgressIPView) {
	for i := 1; i < len(ips); i++ {
		for j := i; j > 0 && (ips[j].Samples > ips[j-1].Samples ||
			(ips[j].Samples == ips[j-1].Samples && ips[j].IP < ips[j-1].IP)); j-- {
			ips[j], ips[j-1] = ips[j-1], ips[j]
		}
	}
}

// PathSample is one recorded path trace.
type PathSample struct {
	ID          int64     `json:"id"`
	TargetID    int64     `json:"target_id"`
	TargetName  string    `json:"target_name"`
	Vantage     string    `json:"vantage"`
	ResolvedIP  string    `json:"resolved_ip,omitempty"`
	Method      string    `json:"method"`
	EndState    string    `json:"end_state"` // reached | max_ttl | error
	ReachedTTL  int       `json:"reached_ttl"`
	ReplyTTL    int       `json:"reply_ttl"`
	VisibleHops int       `json:"visible_hops"`
	Hops        []PathHop `json:"hops"`
	Trigger     string    `json:"trigger"`
	Err         string    `json:"err,omitempty"`
	TracedAt    string    `json:"traced_at"`
}

// PathHop is one responding hop. Silent TTLs carry an empty IP.
type PathHop struct {
	TTL int     `json:"ttl"`
	IP  string  `json:"ip,omitempty"`
	MS  float64 `json:"ms,omitempty"`

	// replyTTL carries the destination reply's IP TTL (ICMP method, via the
	// IP_RECVTTL cmsg) up from the tracer without being persisted.
	replyTTL int
}

// InsertPathSample writes one trace result.
func (s *Store) InsertPathSample(ctx context.Context, p PathSample) (int64, error) {
	hops, err := json.Marshal(p.Hops)
	if err != nil {
		return 0, err
	}
	res, err := s.conn.ExecContext(ctx,
		`INSERT INTO path_samples
		 (target_id, vantage, target_name, resolved_ip, method, end_state, reached_ttl, reply_ttl, visible_hops, hops, trigger, err, traced_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.TargetID, p.Vantage, p.TargetName, p.ResolvedIP, p.Method, p.EndState,
		p.ReachedTTL, p.ReplyTTL, p.VisibleHops, string(hops), p.Trigger, p.Err, p.TracedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LatestPaths returns the newest sample per (target_id, vantage). Optionally
// restricted to one vantage ("" = all).
func (s *Store) LatestPaths(ctx context.Context, vantage string) ([]PathSample, error) {
	q := `SELECT id, target_id, vantage, target_name, resolved_ip, method, end_state,
	             reached_ttl, reply_ttl, visible_hops, hops, trigger, err, traced_at
	      FROM path_samples p
	      WHERE id = (SELECT max(id) FROM path_samples p2
	                  WHERE p2.target_id = p.target_id AND p2.vantage = p.vantage`
	args := []any{}
	if vantage != "" {
		q += ` AND p2.vantage = ?`
		args = append(args, vantage)
	}
	q += `) ORDER BY target_name, vantage`
	return s.queryPaths(ctx, q, args...)
}

// ListPathsByTarget returns the newest-first samples of one target.
func (s *Store) ListPathsByTarget(ctx context.Context, targetID int64, limit int) ([]PathSample, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return s.queryPaths(ctx,
		`SELECT id, target_id, vantage, target_name, resolved_ip, method, end_state,
		        reached_ttl, reply_ttl, visible_hops, hops, trigger, err, traced_at
		 FROM path_samples WHERE target_id = ? ORDER BY id DESC LIMIT ?`, targetID, limit)
}

func (s *Store) queryPaths(ctx context.Context, q string, args ...any) ([]PathSample, error) {
	rows, err := s.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PathSample{}
	for rows.Next() {
		var p PathSample
		var hops string
		if err := rows.Scan(&p.ID, &p.TargetID, &p.Vantage, &p.TargetName, &p.ResolvedIP, &p.Method,
			&p.EndState, &p.ReachedTTL, &p.ReplyTTL, &p.VisibleHops, &hops, &p.Trigger, &p.Err, &p.TracedAt); err != nil {
			return nil, err
		}
		p.Hops = []PathHop{}
		_ = json.Unmarshal([]byte(hops), &p.Hops)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Prune deletes rows older than the given RFC3339 cutoff (retention sweep).
func (s *Store) Prune(ctx context.Context, cutoff string) error {
	for _, t := range []struct{ table, col string }{
		{"egress_rounds", "round_at"},
		{"path_samples", "traced_at"},
		{"probe_phases", "checked_at"},
	} {
		if _, err := s.conn.ExecContext(ctx,
			`DELETE FROM `+t.table+` WHERE `+t.col+` < ?`, cutoff); err != nil {
			return fmt.Errorf("prune %s: %w", t.table, err)
		}
	}
	return nil
}

// --- probe_phases (#717) ----------------------------------------------------

// PhaseRow is one run's per-stage timing breakdown. latency_ms is the run
// total denormalized so the phases chart renders without a probe_results
// join; omitempty on the stages keeps tcp/icmp rows compact on the wire.
type PhaseRow struct {
	TargetID   int64   `json:"target_id"`
	Module     string  `json:"module"`
	Vantage    string  `json:"vantage"`
	CheckedAt  string  `json:"checked_at"`
	ResolvedIP string  `json:"resolved_ip,omitempty"`
	DNSMs      float64 `json:"dns_ms,omitempty"`
	ConnectMs  float64 `json:"connect_ms,omitempty"`
	TLSMs      float64 `json:"tls_ms,omitempty"`
	TTFBMs     float64 `json:"ttfb_ms,omitempty"`
	ReplyTTL   int     `json:"reply_ttl,omitempty"`
	LatencyMs  float64 `json:"latency_ms"`
}

// PhasesResponse is the GET /probe-targets/{id}/phases payload.
type PhasesResponse struct {
	Phases []PhaseRow `json:"phases"`
}

// StorePhase appends one per-stage timing row (#717). It satisfies the
// probetarget.PhasesSink interface (checked at the routes wiring site); a
// nil or data-less Phases is a no-op, double-guarding the engine's gate.
func (s *Store) StorePhase(ctx context.Context, targetID int64, module, vantage, checkedAt string, latencyMs float64, ph *probe.Phases) error {
	if ph == nil || !ph.HasData() {
		return nil
	}
	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO probe_phases
		 (target_id, module, vantage, checked_at, resolved_ip, dns_ms, connect_ms, tls_ms, ttfb_ms, reply_ttl, latency_ms)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		targetID, module, vantage, checkedAt, ph.ResolvedIP, ph.DNSMs, ph.ConnectMs, ph.TLSMs, ph.TTFBMs, ph.ReplyTTL, latencyMs)
	if err != nil {
		return fmt.Errorf("store phase: %w", err)
	}
	return nil
}

// ListPhasesFor returns the newest-first phase rows of one target across all
// vantages (the history modal renders one series per vantage).
func (s *Store) ListPhasesFor(ctx context.Context, targetID int64, limit int) ([]PhaseRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.conn.QueryContext(ctx,
		`SELECT target_id, module, vantage, checked_at, resolved_ip, dns_ms, connect_ms, tls_ms, ttfb_ms, reply_ttl, latency_ms
		 FROM probe_phases WHERE target_id = ? ORDER BY id DESC LIMIT ?`, targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PhaseRow{}
	for rows.Next() {
		var p PhaseRow
		if err := rows.Scan(&p.TargetID, &p.Module, &p.Vantage, &p.CheckedAt, &p.ResolvedIP,
			&p.DNSMs, &p.ConnectMs, &p.TLSMs, &p.TTFBMs, &p.ReplyTTL, &p.LatencyMs); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- quality_episodes (#720) -----------------------------------------------

// InsertEpisode stores a new episode row; JSON fields are marshaled here.
func (s *Store) InsertEpisode(ctx context.Context, e QualityEpisode) (int64, error) {
	metrics, _ := json.Marshal(e.MetricDegraded)
	attr, _ := json.Marshal(e.Attribution)
	res, err := s.conn.ExecContext(ctx,
		`INSERT INTO quality_episodes
		 (kind, vantage_group, target_group, started_at, last_seen_at, windows, metric_degraded, attribution, notified, resolved_at, recover_notified)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Kind, e.VantageGroup, e.TargetGroup, e.StartedAt, e.LastSeenAt, e.Windows,
		string(metrics), string(attr), boolInt(e.Notified), e.ResolvedAt, boolInt(e.RecoverNotified))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateEpisodeWindow bumps the continuation bookkeeping.
func (s *Store) UpdateEpisodeWindow(ctx context.Context, id int64, lastSeenAtISO string) error {
	_, err := s.conn.ExecContext(ctx,
		`UPDATE quality_episodes SET last_seen_at = ?, windows = windows + 1 WHERE id = ?`, lastSeenAtISO, id)
	return err
}

// ResolveEpisode stamps the resolution time.
func (s *Store) ResolveEpisode(ctx context.Context, id int64, resolvedAtISO string) error {
	_, err := s.conn.ExecContext(ctx,
		`UPDATE quality_episodes SET resolved_at = ? WHERE id = ?`, resolvedAtISO, id)
	return err
}

// MarkEpisodeNotified / MarkEpisodeRecoverNotified flip the alert flags.
func (s *Store) MarkEpisodeNotified(ctx context.Context, id int64) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE quality_episodes SET notified = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) MarkEpisodeRecoverNotified(ctx context.Context, id int64) error {
	_, err := s.conn.ExecContext(ctx, `UPDATE quality_episodes SET recover_notified = 1 WHERE id = ?`, id)
	return err
}

// ListActiveEpisodes returns every unresolved episode.
func (s *Store) ListActiveEpisodes(ctx context.Context) ([]QualityEpisode, error) {
	return s.listEpisodes(ctx, `WHERE resolved_at = '' ORDER BY last_seen_at DESC`)
}

// ListEpisodesSince returns episodes started within the window (all states).
func (s *Store) ListEpisodesSince(ctx context.Context, sinceISO string, limit int) ([]QualityEpisode, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	return s.listEpisodes(ctx, `WHERE started_at >= ? ORDER BY started_at DESC LIMIT `+strconv.Itoa(limit), sinceISO)
}

func (s *Store) listEpisodes(ctx context.Context, where string, args ...any) ([]QualityEpisode, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT id, kind, vantage_group, target_group, started_at, last_seen_at, windows,
		        metric_degraded, attribution, notified, resolved_at, recover_notified
		 FROM quality_episodes `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QualityEpisode
	for rows.Next() {
		var e QualityEpisode
		var metricsJSON, attrJSON string
		var notified, recoverNotified int
		if err := rows.Scan(&e.ID, &e.Kind, &e.VantageGroup, &e.TargetGroup, &e.StartedAt, &e.LastSeenAt,
			&e.Windows, &metricsJSON, &attrJSON, &notified, &e.ResolvedAt, &recoverNotified); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(metricsJSON), &e.MetricDegraded)
		_ = json.Unmarshal([]byte(attrJSON), &e.Attribution)
		if e.MetricDegraded == nil {
			e.MetricDegraded = []EpisodeMetric{}
		}
		if e.Attribution == nil {
			e.Attribution = []EpisodeAttribution{}
		}
		e.Notified = notified != 0
		e.RecoverNotified = recoverNotified != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// EgressChangedBetween reports whether the vantage's distinct public-IP set
// changed between adjacent rounds inside [from,to]; returns the first
// change round's timestamp.
func (s *Store) EgressChangedBetween(ctx context.Context, vantage, fromISO, toISO string) (bool, string) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT round_at, ip FROM egress_rounds
		 WHERE vantage = ? AND round_at >= ? AND round_at <= ? AND ok = 1 AND kind != 'local' AND ip != ''
		 ORDER BY round_at`, vantage, fromISO, toISO)
	if err != nil {
		return false, ""
	}
	defer rows.Close()
	type setKey map[string]bool
	var lastSet setKey
	var lastAt string
	for rows.Next() {
		var at, ip string
		if err := rows.Scan(&at, &ip); err != nil {
			return false, ""
		}
		if lastSet == nil {
			lastSet = setKey{ip: true}
			lastAt = at
			continue
		}
		if !lastSet[ip] {
			// New IP not present in the previous round's set.
			return true, at
		}
		_ = lastAt
	}
	return false, ""
}

// PathChangedBetween counts targets whose visible hop sequence changed
// between adjacent samples inside [from,to] for the given vantage.
func (s *Store) PathChangedBetween(ctx context.Context, targetIDs []int64, vantage, fromISO, toISO string) int {
	if len(targetIDs) == 0 {
		return 0
	}
	ids := make([]string, len(targetIDs))
	for i, id := range targetIDs {
		ids[i] = strconv.FormatInt(id, 10)
	}
	rows, err := s.conn.QueryContext(ctx,
		`SELECT target_id, hops, traced_at FROM path_samples
		 WHERE vantage = ? AND traced_at >= ? AND traced_at <= ? AND target_id IN (`+strings.Join(ids, ",")+`)
		 ORDER BY target_id, traced_at`, vantage, fromISO, toISO)
	if err != nil {
		return 0
	}
	defer rows.Close()
	changed := map[int64]bool{}
	lastHops := map[int64]string{}
	for rows.Next() {
		var id int64
		var hops, at string
		if err := rows.Scan(&id, &hops, &at); err != nil {
			return len(changed)
		}
		if prev, ok := lastHops[id]; ok && prev != hops {
			changed[id] = true
		}
		lastHops[id] = hops
	}
	return len(changed)
}
