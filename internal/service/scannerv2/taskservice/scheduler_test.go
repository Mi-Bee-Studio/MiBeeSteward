// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package taskservice

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2/scheduler"
	"mibee-steward/internal/testutil"
)

// These tests cover the scheduler-coupled TriggerTask / CancelTask paths that
// the package doc promised ("exercised separately in the real-scheduler tests
// below") but were never written (#171). The existing tests only covered the
// nil-scheduler guards; these exercise a REAL scheduler with a no-op ScanFunc
// so the with-scheduler behavior (trigger dispatch, disabled/not-found errors,
// cancel-with-no-running-scan) is pinned.

// setupSvcWithScheduler returns a taskservice backed by an in-memory DB and a
// real scheduler whose ScanFunc is a no-op. The scheduler is started so
// TriggerNow can dispatch; Stop is registered for teardown. The no-op ScanFunc
// means triggering a task does not create a run row (the runner is the run
// writer) — these tests assert the dispatch + error-mapping, not run creation.
func setupSvcWithScheduler(t *testing.T) (*Service, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	sched, err := scheduler.New(queries, conn,
		func(context.Context, int64, string, time.Duration, int, int64, *int64) {}, // no-op scan
		nil)
	require.NoError(t, err)
	sched.Start(context.Background())
	t.Cleanup(sched.Stop)
	return New(queries, conn, sched, false), queries
}

// TestTriggerTask_WithScheduler_ReturnsTriggered verifies the happy path: an
// enabled task with a registered cron job fires via the scheduler and
// TriggerTask returns the synthetic "triggered" status (fire-and-forget).
func TestTriggerTask_WithScheduler_ReturnsTriggered(t *testing.T) {
	svc, _ := setupSvcWithScheduler(t)
	ctx := context.Background()

	created, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)

	resp, err := svc.TriggerTask(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, resp.TaskID)
	require.Equal(t, "triggered", resp.Status, "TriggerTask is fire-and-forget → synthetic triggered status")
}

// TestTriggerTask_DisabledTask verifies that a disabled task is rejected with
// ErrScanTaskDisabled BEFORE the scheduler is touched (the enabled check is the
// first guard after the lookup, so the dispatch never runs).
func TestTriggerTask_DisabledTask(t *testing.T) {
	svc, _ := setupSvcWithScheduler(t)
	ctx := context.Background()

	created, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)
	// CreateTask defaults enabled=true (schema DEFAULT 1); disable via UpdateTask.
	_, err = svc.UpdateTask(ctx, created.ID, domain.UpdateScanTaskRequest{Enabled: boolPtr(false)})
	require.NoError(t, err)

	_, err = svc.TriggerTask(ctx, created.ID)
	require.ErrorIs(t, err, ErrScanTaskDisabled, "a disabled task must not be triggerable")
}

// TestTriggerTask_NotFound verifies the not-found path maps to ErrScanTaskNotFound.
func TestTriggerTask_NotFound(t *testing.T) {
	svc, _ := setupSvcWithScheduler(t)
	_, err := svc.TriggerTask(context.Background(), 99999)
	require.ErrorIs(t, err, ErrScanTaskNotFound)
}

// TestCancelTask_NoRunningScan verifies that cancelling a task with no in-flight
// run maps the scheduler's "no running scan" error to ErrScanNotRunning (the
// user-facing signal that there is nothing to cancel).
func TestCancelTask_NoRunningScan(t *testing.T) {
	svc, _ := setupSvcWithScheduler(t)
	ctx := context.Background()

	created, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)

	err = svc.CancelTask(ctx, created.ID)
	require.ErrorIs(t, err, ErrScanNotRunning, "no in-flight run → ErrScanNotRunning")
}

// boolPtr returns a pointer to b (helper for *bool request fields).
func boolPtr(b bool) *bool { return &b }
