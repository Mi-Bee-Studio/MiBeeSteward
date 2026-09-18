// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text.
// A commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	dbsql "mibee-steward/db"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// agentSharedTables lists the tables both the center schema (db/schema.sql)
// and the agent mini-schema (agentSchema) define. The agent reuses the
// sqlc-generated queries built against the CENTER schema, so a column added
// on one side but not the other silently breaks the agent at runtime — the
// schema is applied with CREATE TABLE IF NOT EXISTS, which never touches an
// existing table, so drift only surfaces as "no such column" on a live box
// (that is exactly how #337 happened).
var agentSharedTables = []string{
	"networks", "vlans", "scan_tasks", "scan_task_runs",
	"scan_results", "heartbeat_configs", "devices", "snmp_credentials",
}

func tableColumns(t *testing.T, conn *sql.DB, table string) []string {
	t.Helper()
	rows, err := conn.Query(`SELECT name FROM pragma_table_info(?) ORDER BY name`, table)
	require.NoError(t, err, table)
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c), table)
		cols = append(cols, c)
	}
	require.NoError(t, rows.Err(), table)
	return cols
}

// TestAgentSchema_ParityWithCenterSchema pins the "shapes mirror db/schema.sql"
// promise in agentSchema's doc comment: for every shared table, the agent's
// column set must equal the center's. If this fails after a schema change,
// update agentSchema (and usually agentMigrations for already-deployed boxes)
// in the same PR — do not weaken the assertion.
func TestAgentSchema_ParityWithCenterSchema(t *testing.T) {
	agentConn, err := openAgentDB(t.TempDir() + "/agent.db")
	require.NoError(t, err)
	t.Cleanup(func() { agentConn.Close() })

	centerConn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { centerConn.Close() })
	_, err = centerConn.Exec(dbsql.SchemaSQL)
	require.NoError(t, err)

	for _, tbl := range agentSharedTables {
		require.ElementsMatch(t,
			tableColumns(t, centerConn, tbl),
			tableColumns(t, agentConn, tbl),
			"agent mini-schema drifted from db/schema.sql for table %s — update agentSchema (+ agentMigrations) in the same change", tbl)
	}
}

// TestOpenAgentDB_RunnerSchedulerQueriesCompile smoke-runs the sqlc queries
// the agent's scheduler and runner actually execute every cycle against a
// freshly-provisioned mini-DB. Parity above guards the shape; this guards the
// wiring — a query whose SQL references a column the mini-DB lacks fails HERE
// instead of on a remote agent at 3am.
func TestOpenAgentDB_RunnerSchedulerQueriesCompile(t *testing.T) {
	conn, err := openAgentDB(t.TempDir() + "/agent.db")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	ctx := context.Background()

	// Scheduler tick: list enabled tasks (empty on a fresh DB).
	tasks, err := q.ListEnabledScanTasks(ctx)
	require.NoError(t, err)
	require.Empty(t, tasks)

	// Runner start → finish: create a run row, then complete it.
	run, err := q.CreateScanTaskRun(ctx, db.CreateScanTaskRunParams{
		TaskID: 0, StartedAt: ptrTime(time.Now()),
	})
	require.NoError(t, err)
	require.NotZero(t, run.ID)
	finished := time.Now()
	require.NoError(t, q.UpdateScanTaskRun(ctx, db.UpdateScanTaskRunParams{
		Status: "completed", TotalHosts: 1, AliveHosts: 1, NewHosts: 1, UpdatedHosts: 0,
		DurationMs: 42, ErrorMessage: "", FinishedAt: &finished, ID: run.ID,
	}))

	// Runner results persistence + the API-shaped read-back.
	require.NoError(t, q.BatchInsertScanResults(ctx, db.BatchInsertScanResultsParams{
		TaskID: 0, RunID: &run.ID, Ip: "192.168.62.10", Alive: 1, RttMs: 3,
		Ports:    `[{"port":80,"service":"http"}]`,
		Services: `{"http":{"port":80}}`, SnmpData: `{}`,
		PrometheusDetected: 0, PrometheusUrl: "",
		NodeExporterDetected: 0, NodeExporterUrl: "", NodeExporterData: `{}`,
	}))
	got, err := q.ListScanResults(ctx, db.ListScanResultsParams{
		Column1: nil, TaskID: 0, Column3: nil, Ip: "%",
		Column5: nil, Alive: 1, Limit: 20, Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "192.168.62.10", got[0].Ip)
}

func TestParseDurationOrDefault(t *testing.T) {
	def := 30 * time.Second
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", def},
		{"not-a-duration", def},
		{"45s", 45 * time.Second},
		{"2m", 2 * time.Minute},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, parseDurationOrDefault(tc.in, def), "input %q", tc.in)
	}
}

func TestInitLogger(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	initLogger(config.LogConfig{Level: "debug", Format: "json"})
	_, isJSON := slog.Default().Handler().(*slog.JSONHandler)
	require.True(t, isJSON, "json format must install a JSON handler")
	require.True(t, slog.Default().Handler().Enabled(context.Background(), slog.LevelDebug))

	initLogger(config.LogConfig{Level: "warn", Format: "text"})
	_, isText := slog.Default().Handler().(*slog.TextHandler)
	require.True(t, isText, "non-json format must install a text handler")
	require.False(t, slog.Default().Handler().Enabled(context.Background(), slog.LevelInfo))
	require.True(t, slog.Default().Handler().Enabled(context.Background(), slog.LevelWarn))

	// Unknown level falls back to info (no panic, no error).
	initLogger(config.LogConfig{Level: "verbose", Format: ""})
	require.True(t, slog.Default().Handler().Enabled(context.Background(), slog.LevelInfo))
	require.False(t, slog.Default().Handler().Enabled(context.Background(), slog.LevelDebug))
}
