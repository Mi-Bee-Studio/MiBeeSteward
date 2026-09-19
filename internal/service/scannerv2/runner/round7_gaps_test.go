// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/engine"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

// seedRunTask inserts an enabled scan task and returns its id. The port-spec
// variant embeds an enabled port_scan stage so Run's whitelist branch resolves
// a spec instead of the engine's global list.
func seedRunTask(t *testing.T, conn *sql.DB, pipeline string) int64 {
	t.Helper()
	res, err := conn.Exec(`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, timeout, concurrent_hosts, enabled)
		VALUES ('run-task', '127.0.0.1', '* * * * *', ?, 10, 4, 1)`, pipeline)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// TestRunner_Run_NilEngineMarksFailedRun pins the operator-visibility contract:
// a runner whose engine failed to init still records a FAILED run row for the
// fired task (the trigger must not appear to succeed silently).
func TestRunner_Run_NilEngineMarksFailedRun(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	q := sqldb.New(dbConn)
	ctx := context.Background()

	taskID := seedRunTask(t, dbConn, `{"icmp":{"enabled":true,"timeout":1}}`)
	rn := New(nil, q, dbConn, nil, 0, slog.New(slog.DiscardHandler))
	rn.Run(ctx, taskID, "127.0.0.1", 2*time.Second, 4, false, 0)

	var status, errMsg string
	require.NoError(t, dbConn.QueryRow(
		`SELECT status, error_message FROM scan_task_runs WHERE task_id=?`, taskID).Scan(&status, &errMsg))
	require.Equal(t, "failed", status)
	require.Contains(t, errMsg, "engine not initialized")

	// The task's last-run status is updated too.
	var taskStatus string
	require.NoError(t, dbConn.QueryRow(
		`SELECT last_run_status FROM scan_tasks WHERE id=?`, taskID).Scan(&taskStatus))
	require.Equal(t, "failed", taskStatus)
}

// TestRunner_Run_LoopbackEndToEnd drives the full async-task path over a real
// loopback scan: port whitelist resolution from pipeline_config, engine
// execution, per-host persistence + device bridge, run stats, and the
// report-sink forwarding hook.
func TestRunner_Run_LoopbackEndToEnd(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	q := sqldb.New(dbConn)
	ctx := context.Background()

	// A local TCP listener so the whitelisted port shows OPEN on 127.0.0.1.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	eng, err := engine.NewEngine(dbConn, engine.Config{
		AllowReservedTargets: true,
		PerProbeTimeout:      300 * time.Millisecond,
		PerHostTimeout:       3 * time.Second,
		MaxConcurrentHosts:   4,
	}, nil)
	require.NoError(t, err)

	rn := New(eng, q, dbConn, nil, 0, slog.New(slog.DiscardHandler))
	rn.SetRepo(store.NewSQLiteRepository(dbConn, store.Options{}, nil))

	var sinkCalls, sinkAlive int
	rn.SetReportSink(func(_ context.Context, _ int64, reports []scannerv2.HostReport) {
		sinkCalls++
		for _, r := range reports {
			if r.Alive {
				sinkAlive++
			}
		}
	})

	taskID := seedRunTask(t, dbConn,
		`{"icmp":{"enabled":true,"timeout":1},"port_scan":{"enabled":true,"ports":"`+strconv.Itoa(port)+`"}}`)

	rn.Run(ctx, taskID, "127.0.0.1", 3*time.Second, 4, false, 0)

	// The run completed with the loopback host alive and persisted.
	var status string
	var total, alive int64
	require.NoError(t, dbConn.QueryRow(
		`SELECT status, total_hosts, alive_hosts FROM scan_task_runs WHERE task_id=?`, taskID).Scan(&status, &total, &alive))
	require.Equal(t, "completed", status)
	require.EqualValues(t, 1, total)
	require.EqualValues(t, 1, alive)

	var resultCount int
	require.NoError(t, dbConn.QueryRow(
		`SELECT COUNT(*) FROM scan_results WHERE task_id=? AND ip='127.0.0.1'`, taskID).Scan(&resultCount))
	require.Equal(t, 1, resultCount)

	// The device bridge created a devices row for the live host.
	var devCount int
	require.NoError(t, dbConn.QueryRow(
		`SELECT COUNT(*) FROM devices WHERE ip_address='127.0.0.1'`).Scan(&devCount))
	require.Equal(t, 1, devCount)

	// The report sink was forwarded the alive host exactly once.
	require.Equal(t, 1, sinkCalls)
	require.Equal(t, 1, sinkAlive)
}
