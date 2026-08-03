// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package scheduler

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// newTestScheduler builds a Scheduler over an in-memory DB seeded from the real
// schema (so scan_tasks / scan_task_runs tables exist). The ScanFunc is the
// caller's; pass nil for a no-op. Returns the scheduler, the queries (for
// seeding), and the raw connection (for direct assertions). The scheduler is
// NOT started — tests that need TriggerNow/CancelTask (which require gocron to
// be running) call startTestScheduler instead.
func newTestScheduler(t *testing.T, scanFn ScanFunc) (*Scheduler, *db.Queries, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	// Force a single connection: an in-memory SQLite DB is per-connection (each
	// new pool conn would see an empty DB), and the scheduler's gocron goroutine
	// + the test's main goroutine must share one. This is the standard fix for
	// ":memory:" + connection-pool tests.
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = conn.Close() })
	queries := db.New(conn)
	s, err := New(queries, conn, scanFn, nil)
	require.NoError(t, err)
	t.Cleanup(s.Stop)
	return s, queries, conn
}

// startTestScheduler is newTestScheduler + Start. It also shortens the stale-run
// sweep interval by recreating the scheduler is not possible (private field),
// so the sweeper simply runs at its default 10min — harmless for short tests,
// and Stop (registered via cleanup) terminates it. Seed scan_tasks BEFORE
// calling this so Start's job re-hydration picks them up.
func startTestScheduler(t *testing.T, scanFn ScanFunc) (*Scheduler, *db.Queries, *sql.DB) {
	t.Helper()
	s, queries, conn := newTestScheduler(t, scanFn)
	s.Start(context.Background())
	return s, queries, conn
}

// seedScanTask inserts an enabled scan_tasks row and returns its id. The fields
// executeScan reads (timeout, concurrent_hosts) default to sane values so the
// ScanFunc receives a usable tuning.
func seedScanTask(t *testing.T, conn *sql.DB, id int64, targets string) {
	t.Helper()
	_, err := conn.Exec(
		`INSERT INTO scan_tasks (id, name, targets, cron_expr, timeout, concurrent_hosts, enabled)
		 VALUES (?, ?, ?, '*/10 * * * *', 30, 8, 1)`,
		id, "task-"+filepath.Base(targets), targets,
	)
	require.NoError(t, err)
}

// TestAddJob_ReplacesExisting asserts that registering the same taskID twice
// does not leak a stale entry in jobMap — AddJob must remove-then-register, so
// JobCount reflects distinct tasks, not registration calls.
func TestAddJob_ReplacesExisting(t *testing.T) {
	s, _, _ := newTestScheduler(t, nil)
	const taskID = int64(1)
	require.NoError(t, s.AddJob(taskID, "*/10 * * * *", "10.0.0.0/24"))
	require.Equal(t, 1, s.JobCount(), "first AddJob")
	require.NoError(t, s.AddJob(taskID, "*/5 * * * *", "10.0.0.0/24"))
	require.Equal(t, 1, s.JobCount(), "second AddJob must replace, not append")
}

// TestAddJob_AccumulatesDistinctTasks verifies each distinct taskID gets its
// own job entry (the replace behavior above must not over-prune).
func TestAddJob_AccumulatesDistinctTasks(t *testing.T) {
	s, _, _ := newTestScheduler(t, nil)
	for i := int64(1); i <= 3; i++ {
		require.NoError(t, s.AddJob(i, "*/10 * * * *", "10.0.0.0/24"))
	}
	require.Equal(t, 3, s.JobCount())
	s.RemoveJob(2)
	require.Equal(t, 2, s.JobCount(), "RemoveJob must drop only the named task")
}

// TestTriggerNow_InvokesScanFunc verifies a manual trigger reaches the bound
// ScanFunc with the task's id/targets. gocron runs the task asynchronously, so
// the test waits on a buffered channel with a generous timeout. Requires the
// scheduler to be started (RunNow errors with "scheduler unreachable" otherwise).
func TestTriggerNow_InvokesScanFunc(t *testing.T) {
	type call struct {
		taskID  int64
		targets string
	}
	got := make(chan call, 1)
	const taskID = int64(7)
	const targets = "192.168.0.0/24"
	// Build (not started), seed the task row, THEN start so Start's job
	// re-hydration picks up task 7 and TriggerNow can find it.
	s, _, conn := newTestScheduler(t, func(_ context.Context, id int64, tgt string, _ time.Duration, _ int) {
		select {
		case got <- call{id, tgt}:
		default:
		}
	})
	seedScanTask(t, conn, taskID, targets)
	s.Start(context.Background())

	require.NoError(t, s.TriggerNow(taskID))

	select {
	case c := <-got:
		require.Equal(t, taskID, c.taskID, "ScanFunc taskID")
		require.Equal(t, targets, c.targets, "ScanFunc targets")
	case <-time.After(3 * time.Second):
		t.Fatal("ScanFunc was not invoked within 3s of TriggerNow")
	}
}

// TestCancelTask_CancelsInFlightScan verifies that a running scan observes
// context cancellation when CancelTask is called. The ScanFunc blocks on
// ctx.Done() (the shape a real scan's probes honor); CancelTask must close it.
// Requires the scheduler started so TriggerNow can fire.
func TestCancelTask_CancelsInFlightScan(t *testing.T) {
	const taskID = int64(11)
	const targets = "10.0.0.0/24"
	cancelled := make(chan struct{})
	// Build, seed, THEN start so the seeded task is re-hydrated into the
	// scheduler's jobMap and TriggerNow can fire it.
	s, _, conn := newTestScheduler(t, func(ctx context.Context, _ int64, _ string, _ time.Duration, _ int) {
		<-ctx.Done() // block until cancelled
		close(cancelled)
	})
	seedScanTask(t, conn, taskID, targets)
	s.Start(context.Background())

	require.NoError(t, s.TriggerNow(taskID))

	// Give the scan a moment to start (gocron runs async). Poll cancelFuncs for
	// presence rather than a blind sleep.
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, running := s.cancelFuncs[taskID]
		return running
	}, 3*time.Second, 10*time.Millisecond, "scan did not register its cancelFunc in time")

	require.NoError(t, s.CancelTask(taskID))
	select {
	case <-cancelled:
		// pass — ctx was cancelled
	case <-time.After(2 * time.Second):
		t.Fatal("scan ctx was not cancelled within 2s of CancelTask")
	}
}

// TestCancelTask_NoRunningScanReturnsError asserts the contract documented on
// CancelTask: it errors when nothing is in flight (rather than no-op silently).
func TestCancelTask_NoRunningScanReturnsError(t *testing.T) {
	s, _, _ := newTestScheduler(t, nil)
	err := s.CancelTask(999)
	require.Error(t, err, "CancelTask must error when no scan is running")
}

// TestConcurrentAddRemove_JobCountConsistent hammers the mutex-protected
// jobMap from many goroutines doing add/remove/trigger on the same taskIDs.
// Run under `go test -race` to catch data races on jobMap/cancelFuncs.
func TestConcurrentAddRemove_JobCountConsistent(t *testing.T) {
	const taskID = int64(42)
	// Start first (empty DB → no jobs re-hydrated, harmless), then seed + rely on
	// AddJob (which works regardless of started state) to exercise the mutex.
	s, _, conn := startTestScheduler(t, func(context.Context, int64, string, time.Duration, int) {})
	seedScanTask(t, conn, taskID, "10.0.0.0/24")
	require.NoError(t, s.AddJob(taskID, "*/10 * * * *", "10.0.0.0/24"))

	var wg sync.WaitGroup
	var triggers atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.AddJob(taskID, "*/10 * * * *", "10.0.0.0/24")
				if j%5 == 0 {
					if err := s.TriggerNow(taskID); err == nil {
						triggers.Add(1)
					}
				}
				s.RemoveJob(taskID)
			}
		}()
	}
	wg.Wait()
	// Final state is well-defined regardless of interleaving: the last op wins,
	// JobCount is 0 or 1 (single taskID). The assertion is that it never went
	// negative or raced — covered by -race + the bound check here.
	require.LessOrEqual(t, s.JobCount(), 1, "single taskID → at most 1 job")
}

// TestCleanupStaleRuns_MarksOldRunningAsFailed seeds a scan_task_run whose
// started_at is older than the 1h stale threshold, then calls the private
// cleanupStaleRuns directly (same package) and asserts the row flips to
// 'failed'. This is the recovery path that prevents a hung singleton-reschedule
// job from silently dropping every subsequent trigger forever.
func TestCleanupStaleRuns_MarksOldRunningAsFailed(t *testing.T) {
	s, _, conn := newTestScheduler(t, nil)
	const taskID = int64(1)
	seedScanTask(t, conn, taskID, "10.0.0.0/24")

	// A run that started 2h ago and is still 'running' (the server crashed
	// mid-scan). datetime('now','-2 hour') keeps the test clock-independent.
	_, err := conn.Exec(
		`INSERT INTO scan_task_runs (task_id, status, started_at)
		 VALUES (?, 'running', datetime('now','-2 hour'))`,
		taskID,
	)
	require.NoError(t, err)

	// A recent 'running' run (12 min ago) must be LEFT alone — only >1h is stale.
	const freshRunID = 2
	_, err = conn.Exec(
		`INSERT INTO scan_task_runs (id, task_id, status, started_at)
		 VALUES (?, ?, 'running', datetime('now','-12 minutes'))`,
		freshRunID, taskID,
	)
	require.NoError(t, err)

	// Call cleanup on the SAME scheduler (it shares conn with the seeded rows).
	s.cleanupStaleRuns(context.Background())

	var staleStatus string
	err = conn.QueryRow(
		`SELECT status FROM scan_task_runs WHERE task_id=? AND started_at < datetime('now','-1 hour')`,
		taskID,
	).Scan(&staleStatus)
	require.NoError(t, err)
	require.Equal(t, "failed", staleStatus, "stale run (>1h) must be marked failed")

	var freshStatus string
	err = conn.QueryRow(
		`SELECT status FROM scan_task_runs WHERE id=?`, freshRunID,
	).Scan(&freshStatus)
	require.NoError(t, err)
	require.Equal(t, "running", freshStatus, "recent run (<1h) must be left running")
}
