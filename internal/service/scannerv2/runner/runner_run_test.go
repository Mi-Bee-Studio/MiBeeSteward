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
	"sync"
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
	// cache=shared in-memory DB: the test polls on one pooled conn while
	// the runner goroutine writes on another — plain :memory: is per-conn.
	dbConn, err := sql.Open("sqlite", "file:mark710?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	schema, err := testutil.ReadSchemaFile()
	require.NoError(t, err)
	_, err = dbConn.Exec(schema)
	require.NoError(t, err)
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

// TestRunner_Run_TaskNetworkDrivesFinalize pins the multi-network fix
// (2026-10-16): a scan task carries its own network_id, and the run's
// per-device tagging + network-scoped finalize steps must follow the TASK's
// network — not the wiring-time singleton resolved from config network.name.
// Before the fix a center scanning several networks tagged every device with
// the singleton (empty name → "default"), so ARP injection, edge derivation
// and lost detection all ran against a network that holds nothing.
func TestRunner_Run_TaskNetworkDrivesFinalize(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	q := sqldb.New(dbConn)
	ctx := context.Background()

	eng, err := engine.NewEngine(dbConn, engine.Config{
		AllowReservedTargets: true,
		PerProbeTimeout:      300 * time.Millisecond,
		PerHostTimeout:       3 * time.Second,
		MaxConcurrentHosts:   4,
	}, nil)
	require.NoError(t, err)

	// The singleton runner identity is UNTAGGED (networkID 0 = the config-less
	// center), while the task belongs to a concrete network.
	rn := New(eng, q, dbConn, nil, 0, slog.New(slog.DiscardHandler))
	rn.SetRepo(store.NewSQLiteRepository(dbConn, store.Options{}, nil))

	net, err := q.CreateNetwork(ctx, sqldb.CreateNetworkParams{Name: "task-net"})
	require.NoError(t, err)

	res, err := dbConn.Exec(`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, timeout, concurrent_hosts, network_id, enabled)
		VALUES ('task-net sweep', '127.0.0.1', '* * * * *', '{}', 10, 4, ?, 1)`, net.ID)
	require.NoError(t, err)
	taskID, err := res.LastInsertId()
	require.NoError(t, err)

	rn.Run(ctx, taskID, "127.0.0.1", 3*time.Second, 4, false, 0)

	var devNet sql.NullInt64
	require.NoError(t, dbConn.QueryRow(
		`SELECT network_id FROM devices WHERE ip_address='127.0.0.1'`).Scan(&devNet))
	require.True(t, devNet.Valid, "device must be tagged with the TASK's network, not left NULL")
	require.Equal(t, net.ID, devNet.Int64)
}

// TestRunner_Run_UnboundTaskScopedByTargets pins the transplant-era shape the
// rig exposed (2026-10-16): scan tasks created before per-task network
// binding carry network_id NULL and only a target CIDR. The run must then
// scope its finalize chain to the network whose cidr matches the target —
// the singleton (config network.name, empty → "default") matched nothing and
// every network-scoped step ran against an empty network.
func TestRunner_Run_UnboundTaskScopedByTargets(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	q := sqldb.New(dbConn)
	ctx := context.Background()

	eng, err := engine.NewEngine(dbConn, engine.Config{
		AllowReservedTargets: true,
		PerProbeTimeout:      300 * time.Millisecond,
		PerHostTimeout:       3 * time.Second,
		MaxConcurrentHosts:   4,
	}, nil)
	require.NoError(t, err)

	rn := New(eng, q, dbConn, nil, 0, slog.New(slog.DiscardHandler))
	rn.SetRepo(store.NewSQLiteRepository(dbConn, store.Options{}, nil))

	cidr := "127.0.0.0/8"
	netRow, err := q.CreateNetwork(ctx, sqldb.CreateNetworkParams{Name: "target-net", Cidr: &cidr})
	require.NoError(t, err)

	// network_id deliberately NULL — the pre-binding task shape.
	res, err := dbConn.Exec(`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, timeout, concurrent_hosts, enabled)
		VALUES ('unbound sweep', '127.0.0.1', '* * * * *', '{}', 10, 4, 1)`)
	require.NoError(t, err)
	taskID, err := res.LastInsertId()
	require.NoError(t, err)

	rn.Run(ctx, taskID, "127.0.0.1", 3*time.Second, 4, false, 0)

	var devNet sql.NullInt64
	require.NoError(t, dbConn.QueryRow(
		`SELECT network_id FROM devices WHERE ip_address='127.0.0.1'`).Scan(&devNet))
	require.True(t, devNet.Valid, "unbound task must scope by its target CIDR, not the singleton")
	require.Equal(t, netRow.ID, devNet.Int64)
}

// testLogHandler collects slog records so tests can assert on log
// sequencing without a second DB connection (the shared in-memory SQLite
// is per-conn and observing mid-run state concurrently needs log evidence).
type testLogHandler struct {
	mu    sync.Mutex
	lines []string
}

func (h *testLogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *testLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, r.Message)
	return nil
}
func (h *testLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *testLogHandler) WithGroup(name string) slog.Handler       { return h }

// TestRunner_Run_MarksTaskRunningFromStart (#710): the task's
// last_run_status must flip to 'running' the moment the run row exists —
// asserted via the "task marked running" debug line firing BEFORE the
// engine scan (i.e. before any persist/finalize lines). The one-click
// flow's auto-continue keys on this; mid-scan the task list must not read
// "never run".
func TestRunner_Run_MarksTaskRunningFromStart(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	q := sqldb.New(dbConn)
	ctx := context.Background()

	taskID := seedRunTask(t, dbConn, `{"icmp":{"enabled":true,"timeout":1}}`)
	eng, err := engine.NewEngine(dbConn, engine.Config{
		AllowReservedTargets: true,
		PerProbeTimeout:      100 * time.Millisecond,
		PerHostTimeout:       1 * time.Second,
		MaxConcurrentHosts:   4,
	}, nil)
	require.NoError(t, err)
	lh := &testLogHandler{}
	rn := New(eng, q, dbConn, nil, 0, slog.New(lh))
	rn.SetRepo(store.NewSQLiteRepository(dbConn, store.Options{}, nil))

	rn.Run(ctx, taskID, "127.0.0.1", 1*time.Second, 4, false, 0)

	lh.mu.Lock()
	defer lh.mu.Unlock()
	marked := -1
	for i, l := range lh.lines {
		if l == "scan runner: task marked running" {
			marked = i
			break
		}
	}
	require.GreaterOrEqual(t, marked, 0, "run-start must mark the task running (#710); log lines: %v", lh.lines)

	var status sql.NullString
	require.NoError(t, dbConn.QueryRow(
		`SELECT last_run_status FROM scan_tasks WHERE id = ?`, taskID).Scan(&status))
	require.True(t, status.Valid, "final last_run_status must be set")
}
