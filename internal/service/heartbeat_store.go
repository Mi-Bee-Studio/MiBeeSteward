// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mibee-steward/internal/db"
)

// HeartbeatStore is the dedicated time-series store for heartbeat_results AND
// device_liveness. It lives in a SEPARATE SQLite file (data/heartbeat.db) from
// the main CRUD database, because these are high-volume append-only time series
// (~270k rows/day for probe results, ~240k/day for verdicts) that previously
// dominated the main DB's write bandwidth and caused SQLITE_BUSY across
// heartbeat/scan/audit writers.
//
// Writes are batched: each row goes to a buffered channel, and a flush
// goroutine commits them in a single transaction every few seconds (or when the
// buffer fills). This turns ~180 individual INSERTs/tick into 1 multi-row
// INSERT, cutting write load by 1-2 orders of magnitude and keeping it entirely
// off the main DB connection.
//
// Reads (history, stats, isDue, liveness ratio) go through the same *sql.DB via
// sqlc Queries, so the read path is unchanged from the caller's perspective.
type HeartbeatStore struct {
	db       *sql.DB          // dedicated connection to heartbeat.db
	queries  *db.Queries      // sqlc queries bound to the dedicated connection
	ch       chan resultRow   // per-config probe results
	liveCh   chan livenessRow // per-device verdict samples
	cancelMu sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
}

// resultRow is one heartbeat probe result pending a batched write.
type resultRow struct {
	DeviceID     int64
	ConfigID     int64
	Status       string
	LatencyMs    float64
	ErrorMessage string
	CheckedAt    time.Time
}

// livenessRow is one device-level liveness verdict sample pending a batched
// write to device_liveness. Source records WHICH path set the verdict
// ('heartbeat' | 'scan' | 'lease' | 'manual') for debugging the multi-period
// judgment.
type livenessRow struct {
	DeviceID  int64
	Status    string // 'online' | 'offline' | 'unknown'
	Source    string
	CheckedAt time.Time
}

// heartbeatSchema is the DDL for the dedicated heartbeat DB. It holds TWO
// time-series tables: heartbeat_results (per-config probe results) and
// device_liveness (per-device online/offline VERDICT series). Both live here
// because both are high-volume append-only time series isolated from the main
// CRUD database for the same reason (write-bandwidth contention). Neither has
// foreign keys (cross-DB FKs are impossible in SQLite); cascade-on-device-delete
// is handled in the application layer instead.
//
// device_liveness is the device-level liveness series consumed by the
// change-detection engine's multi-period jitter-vs-transition judgment. It
// stores the VERDICT (online/offline/unknown) decided by applyDeviceVerdict /
// scan / lease paths — NOT the per-config probe results (those are in
// heartbeat_results). Storing the verdict once, at the point it is decided,
// lets the change engine query "online ratio over the last N minutes" directly
// instead of replaying the N-config OR-aggregation that produced the verdict
// (which would give wrong ratios for multi-config devices). It is DISPOSABLE:
// devices.status is the source of truth; this table is a derived cache that can
// be dropped and rebuilt from scans/heartbeats.
const heartbeatSchema = `
CREATE TABLE IF NOT EXISTS heartbeat_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    config_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('success', 'fail', 'timeout')),
    latency_ms REAL NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_heartbeat_results_device ON heartbeat_results(device_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_heartbeat_results_checked_at ON heartbeat_results(checked_at);
CREATE INDEX IF NOT EXISTS idx_heartbeat_results_config ON heartbeat_results(config_id);

CREATE TABLE IF NOT EXISTS device_liveness (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('online', 'offline', 'unknown')),
    source TEXT NOT NULL,
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_device_liveness_device ON device_liveness(device_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_device_liveness_checked_at ON device_liveness(checked_at);
`

const (
	flushInterval  = 5 * time.Second // flush at least this often
	flushBatchSize = 200             // or when this many rows are buffered
	channelBuffer  = 1024            // max in-flight results before backpressure
)

// OpenHeartbeatStore opens (creating if needed) the dedicated heartbeat.db,
// applies time-series-tuned pragmas, creates the schema, and starts the flush
// goroutine. Close must be called at shutdown to flush remaining buffered rows.
func OpenHeartbeatStore(dbPath string) (*HeartbeatStore, error) {
	// Ensure the parent dir exists (same dir as the main mibee.db).
	if dir := filepath.Dir(dbPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create heartbeat db dir: %w", err)
		}
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open heartbeat db: %w", err)
	}
	// Single writer connection. The time-series DB has exactly one writer (the
	// flush goroutine) plus occasional reads; a single connection + WAL means
	// reads never block the writer and there's never a write/write contention.
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	// Pragmas tuned for a high-volume append-only workload: NORMAL sync (safe
	// under WAL, faster commits), a smaller cache (this DB is bounded by
	// retention sweep), and frequent WAL checkpoints so the -wal file doesn't
	// grow unbounded between sweeps.
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-32000",
		"PRAGMA wal_autocheckpoint=1000",
	} {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("heartbeat db pragma %q: %w", p, err)
		}
	}
	if _, err := conn.Exec(heartbeatSchema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("heartbeat db schema: %w", err)
	}

	s := &HeartbeatStore{
		db:      conn,
		queries: db.New(conn),
		ch:      make(chan resultRow, channelBuffer),
		liveCh:  make(chan livenessRow, channelBuffer),
		done:    make(chan struct{}),
	}
	return s, nil
}

// Start launches the background flush goroutine that batches buffered results
// into periodic multi-row INSERTs. The cancel func is assigned synchronously
// (before the goroutine launches) under the mutex, so a concurrent Close() —
// which NewRouter's caller (e.g. a test invoking Stop() right after NewRouter
// returns) may issue while this Start() is still racing onto its goroutine —
// never observes an unset cancel. Mirrors HeartbeatService.Start's pattern.
func (s *HeartbeatStore) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelMu.Lock()
	s.cancel = cancel
	s.cancelMu.Unlock()
	go s.flushLoop(ctx)
}

// Enqueue adds a heartbeat result to the write buffer. It is non-blocking up to
// the channel capacity; if the buffer is full (probe faster than flush can
// drain — only under extreme load), the row is dropped with a warning rather
// than stalling the heartbeat tick (a dropped history row doesn't affect the
// status verdict, which is decided from the probe result directly).
func (s *HeartbeatStore) Enqueue(r resultRow) {
	select {
	case s.ch <- r:
	default:
		slog.Warn("heartbeat store buffer full, dropping result row",
			"device_id", r.DeviceID, "config_id", r.ConfigID)
	}
}

// EnqueueLiveness adds a device-level verdict sample to the device_liveness
// write buffer. Same non-blocking/drop semantics as Enqueue: a dropped sample
// never affects the current devices.status (source of truth) — it only leaves a
// gap in the liveness time series, which the multi-period judgment tolerates
// (online-ratio is computed over whatever samples exist in the window).
func (s *HeartbeatStore) EnqueueLiveness(r livenessRow) {
	select {
	case s.liveCh <- r:
	default:
		slog.Warn("heartbeat store buffer full, dropping liveness sample",
			"device_id", r.DeviceID, "source", r.Source)
	}
}

// Queries returns the sqlc Queries bound to the dedicated heartbeat DB, for
// read paths (history, stats, isDue) and the retention sweep.
func (s *HeartbeatStore) Queries() *db.Queries { return s.queries }

// DB returns the underlying connection (used by the cleanup sweeper for raw
// batched DELETE and by Close).
func (s *HeartbeatStore) DB() *sql.DB { return s.db }

// flushLoop drains BOTH buffers (probe results + liveness samples) on a timer
// and when either fills, committing each kind in its own multi-row transaction
// until the context is cancelled.
func (s *HeartbeatStore) flushLoop(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]resultRow, 0, flushBatchSize)
	liveBatch := make([]livenessRow, 0, flushBatchSize)

	flushResults := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.commitBatch(ctx, batch); err != nil {
			slog.Error("heartbeat batch insert failed", "rows", len(batch), "error", err)
		}
		batch = batch[:0]
	}
	flushLiveness := func() {
		if len(liveBatch) == 0 {
			return
		}
		if err := s.commitLivenessBatch(ctx, liveBatch); err != nil {
			slog.Error("device_liveness batch insert failed", "rows", len(liveBatch), "error", err)
		}
		liveBatch = liveBatch[:0]
	}
	flushAll := func() {
		flushResults()
		flushLiveness()
	}

	for {
		select {
		case <-ctx.Done():
			// Final drain on shutdown — flush whatever is buffered so we don't
			// lose recent results when the process stops.
			ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			for len(s.ch) > 0 {
				batch = append(batch, <-s.ch)
				if len(batch) >= flushBatchSize {
					flushResults()
				}
			}
			for len(s.liveCh) > 0 {
				liveBatch = append(liveBatch, <-s.liveCh)
				if len(liveBatch) >= flushBatchSize {
					flushLiveness()
				}
			}
			flushAll()
			cancel()
			_ = ctx2
			return
		case r := <-s.ch:
			batch = append(batch, r)
			if len(batch) >= flushBatchSize {
				flushResults()
			}
		case r := <-s.liveCh:
			liveBatch = append(liveBatch, r)
			if len(liveBatch) >= flushBatchSize {
				flushLiveness()
			}
		case <-ticker.C:
			flushAll()
		}
	}
}

// commitBatch writes rows in a single multi-row INSERT inside one transaction.
// Building one INSERT with N value tuples is dramatically cheaper than N
// separate INSERTs (one fsync per transaction vs N).
func (s *HeartbeatStore) commitBatch(ctx context.Context, rows []resultRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Build "INSERT INTO heartbeat_results (device_id, config_id, status,
	// latency_ms, error_message, checked_at) VALUES (?),(?),..." with len(rows)
	// tuples. Placeholder count = rows × 6.
	var b strings.Builder
	b.WriteString("INSERT INTO heartbeat_results (device_id, config_id, status, latency_ms, error_message, checked_at) VALUES ")
	args := make([]any, 0, len(rows)*6)
	for i, r := range rows {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("(?,?,?,?,?,?)")
		// Format checked_at as RFC3339 rather than passing a time.Time directly.
		// modernc.org/sqlite serializes time.Time via Time.String(), which
		// appends a monotonic clock reading ("... +0000 UTC m=+45450.82...").
		// That suffix breaks SQLite's date()/time() functions (they return NULL),
		// making per-day aggregates and retention sweeps rely on substr hacks.
		// A plain UTC RFC3339 string parses cleanly and sorts correctly. Legacy
		// rows age out via the 7-day retention sweeper.
		args = append(args, r.DeviceID, r.ConfigID, r.Status, r.LatencyMs, r.ErrorMessage,
			r.CheckedAt.UTC().Format(time.RFC3339))
	}
	if _, err := tx.ExecContext(ctx, b.String(), args...); err != nil {
		return fmt.Errorf("batch insert: %w", err)
	}
	return tx.Commit()
}

// commitLivenessBatch writes device_liveness rows in a single multi-row INSERT
// inside one transaction (mirrors commitBatch for the verdict series).
func (s *HeartbeatStore) commitLivenessBatch(ctx context.Context, rows []livenessRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var b strings.Builder
	b.WriteString("INSERT INTO device_liveness (device_id, status, source, checked_at) VALUES ")
	args := make([]any, 0, len(rows)*4)
	for i, r := range rows {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("(?,?,?,?)")
		// Same RFC3339-string workaround as commitBatch (see comment there): a
		// plain UTC string sorts correctly and keeps SQLite date() usable for
		// any future time-bucketed aggregate.
		args = append(args, r.DeviceID, r.Status, r.Source,
			r.CheckedAt.UTC().Format(time.RFC3339))
	}
	if _, err := tx.ExecContext(ctx, b.String(), args...); err != nil {
		return fmt.Errorf("liveness batch insert: %w", err)
	}
	return tx.Commit()
}

// Close cancels the flush loop, waits for it to finish (including the final
// drain), then closes the DB connection.
func (s *HeartbeatStore) Close() error {
	s.cancelMu.Lock()
	cancel := s.cancel
	s.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	<-s.done // wait for flushLoop to exit (does its final drain)
	return s.db.Close()
}

// DeleteByDevice removes all heartbeat_results AND device_liveness rows for a
// device. This replaces the ON DELETE CASCADE foreign key that existed when
// these tables lived in the main DB (cross-DB FKs aren't possible). Called when
// a device is deleted.
func (s *HeartbeatStore) DeleteByDevice(ctx context.Context, deviceID int64) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM heartbeat_results WHERE device_id = ?", deviceID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM device_liveness WHERE device_id = ?", deviceID)
	return err
}

// DeleteAllLiveness wipes the entire device_liveness table (keeps
// heartbeat_results). Used by the rebuild path: devices.status is the source of
// truth, so dropping the derived verdict series and letting it refill from
// subsequent scans/heartbeats loses nothing authoritative.
func (s *HeartbeatStore) DeleteAllLiveness(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM device_liveness")
	return err
}

// LivenessPoint is one sample in a device's liveness series.
type LivenessPoint struct {
	Status    string
	Source    string
	CheckedAt time.Time
}

// OnlineRatio returns the fraction of a device's liveness samples (within the
// given window ending now) whose status was 'online'. This is the core
// jitter-vs-transition signal the change-detection engine thresholds on: a
// flaky host hovers near 0.5 over a short window, a genuinely-down host sits at
// 0, a healthy one at 1. Returns (ratio, sampleCount, error). A zero
// sampleCount means the window has no data yet (cold start / retention gap) —
// callers treat the ratio as unknown and fall back to devices.status.
//
// The cutoff is formatted as RFC3339 (not passed as time.Time) because
// device_liveness.checked_at is stored as RFC3339 TEXT (the modernc
// monotonic-suffix workaround): a time.Time arg serializes to a different
// string shape that sorts wrong against the stored values. See commitBatch.
func (s *HeartbeatStore) OnlineRatio(ctx context.Context, deviceID int64, window time.Duration) (float64, int64, error) {
	cutoff := time.Now().Add(-window).UTC().Format(time.RFC3339)
	var ratio float64
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT
		CAST(COALESCE(CAST(SUM(CASE WHEN status='online' THEN 1 ELSE 0 END) AS REAL)/COUNT(*),0.0) AS REAL),
		CAST(COUNT(*) AS INTEGER)
		FROM device_liveness WHERE device_id=? AND checked_at>=?`, deviceID, cutoff).Scan(&ratio, &count)
	if err != nil {
		return 0, 0, err
	}
	return ratio, count, nil
}

// OfflineDuration returns how long a device has been continuously offline: the
// elapsed time since its most recent 'online' sample. This distinguishes "just
// went down" from "has been down for an hour" — the change engine uses it to
// gate the short-term confirmation window. Returns (duration, ok): ok=false
// when the device has never been seen online (or samples aged out); callers
// then rely on devices.status instead of guessing the duration.
func (s *HeartbeatStore) OfflineDuration(ctx context.Context, deviceID int64) (time.Duration, bool, error) {
	var lastStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT checked_at FROM device_liveness WHERE device_id=? AND status='online' ORDER BY checked_at DESC LIMIT 1`,
		deviceID).Scan(&lastStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, false, nil // never seen online
		}
		return 0, false, err
	}
	last, err := time.Parse(time.RFC3339, lastStr)
	if err != nil {
		return 0, false, err
	}
	return time.Since(last), true, nil
}

// LivenessHistory returns the raw verdict samples for a device in [from, to],
// newest-first. Used by the device-detail trend chart and for debugging the
// multi-period judgment. Capped by limit (the caller pages). Bounds are
// formatted as RFC3339 (see OnlineRatio for the rationale).
func (s *HeartbeatStore) LivenessHistory(ctx context.Context, deviceID int64, from, to time.Time, limit int64) ([]LivenessPoint, error) {
	fromStr := from.UTC().Format(time.RFC3339)
	toStr := to.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, source, checked_at FROM device_liveness
		 WHERE device_id=? AND checked_at>=? AND checked_at<=?
		 ORDER BY checked_at DESC LIMIT ?`,
		deviceID, fromStr, toStr, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LivenessPoint, 0)
	for rows.Next() {
		var p LivenessPoint
		var checkedStr string
		if err := rows.Scan(&p.Status, &p.Source, &checkedStr); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, checkedStr); err == nil {
			p.CheckedAt = t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// keep slog referenced for the warn/error logs above
var _ = slog.Default
