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
	"time"

	"mibee-steward/internal/db"
)

// HeartbeatStore is the dedicated time-series store for heartbeat_results.
// It lives in a SEPARATE SQLite file (data/heartbeat.db) from the main CRUD
// database, because heartbeat_results is a high-volume append-only time series
// (~270k rows/day) that previously dominated the main DB's write bandwidth and
// caused SQLITE_BUSY across heartbeat/scan/audit writers.
//
// Writes are batched: each probe result goes to a buffered channel, and a
// flush goroutine commits them in a single transaction every few seconds (or
// when the buffer fills). This turns ~180 individual INSERTs/tick into 1
// multi-row INSERT, cutting write load by 1-2 orders of magnitude and keeping
// it entirely off the main DB connection.
//
// Reads (history, stats, isDue) go through the same *sql.DB via sqlc Queries,
// so the read path is unchanged from the caller's perspective.
type HeartbeatStore struct {
	db      *sql.DB     // dedicated connection to heartbeat.db
	queries *db.Queries // sqlc queries bound to the dedicated connection
	ch      chan resultRow
	cancel  context.CancelFunc
	done    chan struct{}
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

// heartbeatSchema is the heartbeat_results table DDL for the dedicated DB.
// It intentionally has NO foreign keys (cross-DB FKs are impossible in SQLite);
// cascade-on-device-delete is handled in the application layer instead.
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
		done:    make(chan struct{}),
	}
	return s, nil
}

// Start launches the background flush goroutine that batches buffered results
// into periodic multi-row INSERTs.
func (s *HeartbeatStore) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
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

// Queries returns the sqlc Queries bound to the dedicated heartbeat DB, for
// read paths (history, stats, isDue) and the retention sweep.
func (s *HeartbeatStore) Queries() *db.Queries { return s.queries }

// DB returns the underlying connection (used by the cleanup sweeper for raw
// batched DELETE and by Close).
func (s *HeartbeatStore) DB() *sql.DB { return s.db }

// flushLoop drains the buffer on a timer and when it fills, committing each
// batch in a single transaction until the context is cancelled.
func (s *HeartbeatStore) flushLoop(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]resultRow, 0, flushBatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.commitBatch(ctx, batch); err != nil {
			slog.Error("heartbeat batch insert failed", "rows", len(batch), "error", err)
		}
		batch = batch[:0]
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
					flush()
				}
			}
			flush()
			cancel()
			_ = ctx2
			return
		case r := <-s.ch:
			batch = append(batch, r)
			if len(batch) >= flushBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
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
		args = append(args, r.DeviceID, r.ConfigID, r.Status, r.LatencyMs, r.ErrorMessage, r.CheckedAt)
	}
	if _, err := tx.ExecContext(ctx, b.String(), args...); err != nil {
		return fmt.Errorf("batch insert: %w", err)
	}
	return tx.Commit()
}

// Close cancels the flush loop, waits for it to finish (including the final
// drain), then closes the DB connection.
func (s *HeartbeatStore) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	<-s.done // wait for flushLoop to exit (does its final drain)
	return s.db.Close()
}

// DeleteByDevice removes all heartbeat_results for a device. This replaces the
// ON DELETE CASCADE foreign key that existed when heartbeat_results lived in
// the main DB (cross-DB FKs aren't possible). Called when a device is deleted.
func (s *HeartbeatStore) DeleteByDevice(ctx context.Context, deviceID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM heartbeat_results WHERE device_id = ?", deviceID)
	return err
}

// keep slog referenced for the warn/error logs above
var _ = slog.Default
