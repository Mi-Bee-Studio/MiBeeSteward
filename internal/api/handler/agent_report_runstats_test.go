// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You should use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// seedAgentTaskAndRun inserts a scan task bound to the agent's network plus a
// "running" run row — the state dispatchAgentScan leaves behind (#390) — and
// returns the run id.
func seedAgentTaskAndRun(t *testing.T, db *sql.DB, networkID int64) int64 {
	t.Helper()
	ctx := context.Background()
	res, err := db.ExecContext(ctx,
		`INSERT INTO scan_tasks (name, targets, cron_expr, network_id) VALUES (?, ?, ?, ?)`,
		"agent-scan", "192.168.62.0/24", "*/5 * * * *", networkID)
	require.NoError(t, err)
	taskID, err := res.LastInsertId()
	require.NoError(t, err)
	started := time.Now().Add(-2 * time.Minute)
	res, err = db.ExecContext(ctx,
		`INSERT INTO scan_task_runs (task_id, status, started_at) VALUES (?, 'running', ?)`,
		taskID, started)
	require.NoError(t, err)
	runID, err := res.LastInsertId()
	require.NoError(t, err)
	return runID
}

func fetchRun(t *testing.T, db *sql.DB, runID int64) (status string, total, alive, newH, upd int64, duration int64) {
	t.Helper()
	err := db.QueryRowContext(context.Background(),
		`SELECT status, total_hosts, alive_hosts, new_hosts, updated_hosts, duration_ms FROM scan_task_runs WHERE id = ?`,
		runID).Scan(&status, &total, &alive, &newH, &upd, &duration)
	require.NoError(t, err)
	return
}

// TestAgentReport_BackfillsRunningRunStats: the first host-carrying report for
// a network closes its pending dispatch-run with real counts instead of the
// old 6ms "completed" marker (#390).
func TestAgentReport_BackfillsRunningRunStats(t *testing.T) {
	srv, db, token, networkID := setupAgentIngestServer(t)
	runID := seedAgentTaskAndRun(t, db, networkID)

	code, body := postReport(t, srv, token, map[string]interface{}{
		"agent_id": "agent-62",
		"hosts": []map[string]interface{}{
			{"ip": "192.168.62.41", "alive": true, "mac": "aa:bb:cc:dd:ee:41", "inferred_type": "camera"},
			{"ip": "192.168.62.42", "alive": true, "mac": "aa:bb:cc:dd:ee:42", "inferred_type": "pc"},
		},
	})
	require.Equal(t, 200, code, "body: %v", body)

	status, total, alive, newH, upd, duration := fetchRun(t, db, runID)
	require.Equal(t, "completed", status)
	require.Equal(t, int64(2), total)
	require.Equal(t, int64(2), alive)
	require.Equal(t, int64(2), newH, "both hosts are first sightings")
	require.Equal(t, int64(0), upd)
	require.Greater(t, duration, int64(0), "duration should reflect the pending window, not the 6ms dispatch")
}

// The stable-hash fast path closes the run too — with the reported host count
// and zero add/update (the bridge is skipped by design).
func TestAgentReport_BackfillsRunOnStablePath(t *testing.T) {
	srv, db, token, networkID := setupAgentIngestServer(t)

	hosts := []map[string]interface{}{
		{"ip": "192.168.62.41", "alive": true, "mac": "aa:bb:cc:dd:ee:41", "inferred_type": "camera"},
	}
	report := map[string]interface{}{"agent_id": "agent-62", "hosts": hosts}
	code, body := postReportWithHeader(t, srv, token, "X-Network-State-Hash", "h1", report)
	require.Equal(t, 200, code, "body: %v", body)

	// Seed the pending run BETWEEN the reports: the next (stable) report must
	// be the one that closes it, via the fast path.
	runID := seedAgentTaskAndRun(t, db, networkID)
	code, body = postReportWithHeader(t, srv, token, "X-Network-State-Hash", "h1", report)
	require.Equal(t, 200, code, "body: %v", body)
	require.Equal(t, true, body["stable"])

	status, _, alive, newH, _, duration := fetchRun(t, db, runID)
	require.Equal(t, "completed", status)
	require.Equal(t, int64(1), alive)
	require.Equal(t, int64(0), newH, "fast path adds nothing by design")
	require.Greater(t, duration, int64(0))
}

// A report for a network with NO pending run is a no-op: the handler still
// 200s and no run rows change (networks without scan tasks report fine).
func TestAgentReport_BackfillNoPendingRunIsNoop(t *testing.T) {
	srv, db, token, networkID := setupAgentIngestServer(t)
	_ = networkID

	var runsBefore int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM scan_task_runs`).Scan(&runsBefore))
	require.Equal(t, 0, runsBefore, "no tasks seeded → no runs")

	code, body := postReport(t, srv, token, map[string]interface{}{
		"agent_id": "agent-62",
		"hosts":    []map[string]interface{}{{"ip": "192.168.62.41", "alive": true, "mac": "aa:bb:cc:dd:ee:41"}},
	})
	require.Equal(t, 200, code, "body: %v", body)

	var runsAfter int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM scan_task_runs`).Scan(&runsAfter))
	require.Equal(t, 0, runsAfter, "backfill must not create rows when no run is pending")
}
