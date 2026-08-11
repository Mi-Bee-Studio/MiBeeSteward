// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package cleanup

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// These tests pin the retention-sweep mechanics (cutoff + sweepBatched) and one
// end-to-end table prune, which were previously untested (#171). The sweep
// prunes high-volume detail tables; the load-bearing invariants are:
//   - days<=0 NEVER deletes (misconfig must not wipe a table),
//   - deletion loops in batches until a batch is under-sized (backlog exhausted),
//   - a mid-sweep cancel/error keeps the rows already deleted (best-effort).
// A regression here silently over- or under-prunes production data.

// TestCutoff_ZeroDaysGuard pins the delete-everything guard: a non-positive
// retention window returns the zero time, which sweepBatched treats as "leave
// the table alone". Without this a 0-day config would delete EVERY row.
func TestCutoff_ZeroDaysGuard(t *testing.T) {
	require.True(t, cutoff(0).IsZero(), "0 days must return zero time (no-op sentinel)")
	require.True(t, cutoff(-1).IsZero(), "negative days must also return zero time")
	// A positive window lands roughly at now - days (allow clock skew).
	cut := cutoff(30)
	require.False(t, cut.IsZero())
	require.WithinDuration(t, time.Now().AddDate(0, 0, -30), cut, 5*time.Second)
}

// TestSweepBatched_ZeroDaysNeverDeletes asserts the del callback is never
// invoked when days<=0 — the single most important sweep safety property.
func TestSweepBatched_ZeroDaysNeverDeletes(t *testing.T) {
	svc := New(nil, nil, nil, nil, config.RetentionConfig{BatchSize: 10, SweepIntervalHours: 1})
	calls := 0
	got := svc.sweepBatched(context.Background(), "t", 0, func(time.Time, int64) (int64, error) {
		calls++
		return 1, nil
	})
	require.Equal(t, int64(0), got, "days<=0 must delete nothing")
	require.Equal(t, 0, calls, "del callback must not run when days<=0")
}

// TestSweepBatched_LoopsUntilBatchExhausted verifies the batching loop: while a
// batch returns exactly batchSize rows the sweep keeps going; the first
// under-sized batch stops it. Total is the sum across batches.
func TestSweepBatched_LoopsUntilBatchExhausted(t *testing.T) {
	const batch = 3
	svc := New(nil, nil, nil, nil, config.RetentionConfig{BatchSize: batch, SweepIntervalHours: 1})
	// Plan: two full batches (3 each) then a partial (1) → 4 calls, 7 rows total.
	plan := []int64{batch, batch, 1}
	idx := 0
	got := svc.sweepBatched(context.Background(), "t", 7, func(_ time.Time, limit int64) (int64, error) {
		require.Equal(t, int64(batch), limit, "each call must be capped at batchSize")
		n := plan[idx]
		idx++
		return n, nil
	})
	require.Equal(t, int64(7), got, "total deleted = sum of all batches")
	require.Equal(t, len(plan), idx, "loop must stop once a batch is under-sized")
}

// TestSweepBatched_ErrorReturnsTotalSoFar asserts that a del error aborts the
// loop but keeps the rows already deleted (best-effort: a transient failure
// mid-table does not undo earlier batches).
func TestSweepBatched_ErrorReturnsTotalSoFar(t *testing.T) {
	svc := New(nil, nil, nil, nil, config.RetentionConfig{BatchSize: 5, SweepIntervalHours: 1})
	calls := 0
	got := svc.sweepBatched(context.Background(), "t", 7, func(time.Time, int64) (int64, error) {
		calls++
		if calls == 2 {
			return 0, errors.New("boom")
		}
		return 5, nil // first batch full → loop continues
	})
	require.Equal(t, int64(5), got, "rows deleted before the error are kept")
	require.Equal(t, 2, calls, "loop must stop on the first error")
}

// TestSweepBatched_CancelledMidSweep asserts a cancelled context stops the loop
// and returns whatever was deleted so far.
func TestSweepBatched_CancelledMidSweep(t *testing.T) {
	svc := New(nil, nil, nil, nil, config.RetentionConfig{BatchSize: 2, SweepIntervalHours: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled → loop body never runs
	got := svc.sweepBatched(ctx, "t", 5, func(time.Time, int64) (int64, error) {
		t.Fatal("del must not run when ctx is already cancelled")
		return 0, nil
	})
	require.Equal(t, int64(0), got)
}

// TestPruneAuditLogs_WindowPrunesOldKeepsNew is the end-to-end retention prune
// for a detail table: rows older than the window are deleted, newer ones kept.
func TestPruneAuditLogs_WindowPrunesOldKeepsNew(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.AddDate(0, 0, -100) // beyond a 30d window
	seedAuditLog(t, conn, &old)
	seedAuditLog(t, conn, &old)
	seedAuditLog(t, conn, &now)
	seedAuditLog(t, conn, &now)

	svc := New(queries, nil, nil, nil, config.RetentionConfig{
		AuditLogsDays:      30,
		BatchSize:          1000,
		SweepIntervalHours: 1,
	})
	svc.pruneAuditLogs(ctx)

	require.Equal(t, int64(2), countAuditLogs(t, conn), "2 old rows pruned, 2 fresh kept")
}

// TestPruneAuditLogs_ZeroDaysGuard is the end-to-end safety guard: a 0-day
// config must leave the table untouched (no delete-everything).
func TestPruneAuditLogs_ZeroDaysGuard(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	old := time.Now().UTC().AddDate(0, 0, -365)
	seedAuditLog(t, conn, &old)
	seedAuditLog(t, conn, &old)

	svc := New(queries, nil, nil, nil, config.RetentionConfig{
		AuditLogsDays:      0, // disabled → must prune nothing
		BatchSize:          1000,
		SweepIntervalHours: 1,
	})
	svc.pruneAuditLogs(ctx)

	require.Equal(t, int64(2), countAuditLogs(t, conn), "0-day window must not delete anything")
}

// seedAuditLog inserts one audit_logs row with the given created_at (NULL
// user_id avoids the users FK). A nil ts uses the column default (now).
func seedAuditLog(t *testing.T, conn *sql.DB, ts *time.Time) {
	t.Helper()
	if ts == nil {
		_, err := conn.Exec(`INSERT INTO audit_logs (action, resource_type) VALUES ('test', 't')`)
		require.NoError(t, err)
		return
	}
	_, err := conn.Exec(`INSERT INTO audit_logs (action, resource_type, created_at) VALUES ('test', 't', ?)`, *ts)
	require.NoError(t, err)
}

func countAuditLogs(t *testing.T, conn *sql.DB) int64 {
	t.Helper()
	var n int64
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&n))
	return n
}
