// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"

	"github.com/stretchr/testify/require"
)

func setupDashboardService(t *testing.T) (*DashboardService, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	cfg := &config.Config{}
	return NewDashboardService(conn, cfg), conn
}

func seedOverviewDevice(t *testing.T, conn *sql.DB, name, dtype, status, ip, location string, networkID int64, lastScanned string) {
	t.Helper()
	_, err := conn.Exec(`INSERT INTO devices (device_uuid, name, type, status, ip_address, location, network_id, last_scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "uuid-"+name, name, dtype, status, ip, location, networkID, lastScanned)
	require.NoError(t, err)
}

func seedScanTask(t *testing.T, conn *sql.DB, name, targets string, networkID sql.NullInt64, enabled bool) int64 {
	t.Helper()
	res, err := conn.Exec(`INSERT INTO scan_tasks (name, targets, network_id, enabled) VALUES (?, ?, ?, ?)`,
		name, targets, networkID, enabled)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func seedScanRun(t *testing.T, conn *sql.DB, taskID int64, status string, alive, newHosts int, duration int64) int64 {
	t.Helper()
	res, err := conn.Exec(`INSERT INTO scan_task_runs (task_id, status, total_hosts, alive_hosts, new_hosts, duration_ms, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`, taskID, status, alive+newHosts, alive, newHosts, duration)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func TestDashboardOverview_GlobalScopeAggregates(t *testing.T) {
	svc, conn := setupDashboardService(t)
	ctx := context.Background()

	seedOverviewDevice(t, conn, "gw", "router", "online", "10.0.0.1", "Rack A", 1, "2026-01-01 10:00:00")
	seedOverviewDevice(t, conn, "cam", "camera", "online", "10.0.0.2", "", 1, "2026-01-01 10:00:00")
	seedOverviewDevice(t, conn, "pc-1", "pc", "offline", "10.0.0.3", "Desk", 1, "2026-01-02 10:00:00")
	seedOverviewDevice(t, conn, "pc-2", "pc", "offline", "10.0.0.4", "Desk", 1, "2026-01-03 10:00:00")
	seedOverviewDevice(t, conn, "ghost", "other", "unknown", "10.0.0.5", "", 1, "2026-01-04 10:00:00")

	task1 := seedScanTask(t, conn, "lan-scan", "10.0.0.0/24", sql.NullInt64{Int64: 1, Valid: true}, true)
	task2 := seedScanTask(t, conn, "other", "192.168.0.0/24", sql.NullInt64{}, true)
	seedScanRun(t, conn, task1, "completed", 5, 2, 1000)
	seedScanRun(t, conn, task1, "failed", 0, 0, 50)
	seedScanRun(t, conn, task2, "completed", 3, 0, 500)

	out, err := svc.Overview(ctx, domain.Scope{Global: true})
	require.NoError(t, err)

	require.Equal(t, int64(5), out.Devices.Total)
	require.Equal(t, int64(2), out.Devices.Online)
	require.Equal(t, int64(2), out.Devices.Offline)
	require.Equal(t, int64(1), out.Devices.Unknown)
	require.InDelta(t, 0.4, out.Devices.OnlineRate, 1e-9)

	// empty location collapses to the "unknown" bucket (type is CHECK-constrained
	// in the schema, so the NULLIF fallback there stays defensive-only)
	require.Equal(t, map[string]int64{"router": 1, "camera": 1, "pc": 2, "other": 1}, out.Devices.ByType)
	require.Equal(t, map[string]int64{"Rack A": 1, "unknown": 2, "Desk": 2}, out.Devices.ByLocation)

	// abnormal = offline devices, most recently scanned first
	require.Len(t, out.Abnormal, 2)
	require.Equal(t, "pc-2", out.Abnormal[0].Name)
	require.Equal(t, "pc-1", out.Abnormal[1].Name)

	// scanning section: both tasks visible globally, runs scope through tasks
	require.Equal(t, int64(2), out.Scanning.TasksTotal)
	require.Equal(t, int64(3), out.Scanning.RunsTotal)
	require.Len(t, out.Scanning.RecentTasks, 2)
	require.Len(t, out.Scanning.RecentRuns, 3)
	require.Equal(t, map[string]int64{"completed": 2, "failed": 1}, out.Scanning.RunsByStatus)

	// last discovery = most recent completed run
	require.NotNil(t, out.Scanning.LastDiscovery)
	require.Equal(t, int64(5), out.Scanning.LastDiscovery.AliveHosts)
}

func TestDashboardOverview_RestrictedScopeSeesGrantedNetworkOnly(t *testing.T) {
	svc, conn := setupDashboardService(t)
	ctx := context.Background()

	seedOverviewDevice(t, conn, "mine-1", "pc", "online", "10.0.0.1", "A", 1, "2026-01-01 10:00:00")
	seedOverviewDevice(t, conn, "mine-off", "pc", "offline", "10.0.0.2", "A", 1, "2026-01-01 11:00:00")
	seedOverviewDevice(t, conn, "other-net", "server", "online", "10.0.1.1", "B", 2, "2026-01-01 12:00:00")

	grantedTask := seedScanTask(t, conn, "granted", "10.0.0.0/24", sql.NullInt64{Int64: 1, Valid: true}, true)
	seedScanTask(t, conn, "elsewhere", "10.0.1.0/24", sql.NullInt64{Int64: 2, Valid: true}, true)
	seedScanRun(t, conn, grantedTask, "completed", 2, 1, 100)

	out, err := svc.Overview(ctx, domain.Scope{NetworkIDs: []int64{1}})
	require.NoError(t, err)

	require.Equal(t, int64(2), out.Devices.Total)
	require.Equal(t, int64(1), out.Devices.Online)
	require.Equal(t, int64(1), out.Devices.Offline)
	require.Len(t, out.Abnormal, 1)
	require.Equal(t, "mine-off", out.Abnormal[0].Name)

	require.Equal(t, int64(1), out.Scanning.TasksTotal)
	require.Equal(t, int64(1), out.Scanning.RunsTotal)
	require.Equal(t, "granted", out.Scanning.RecentTasks[0].Name)
}

func TestDashboardOverview_EmptyDBRendersZeroState(t *testing.T) {
	svc, _ := setupDashboardService(t)

	out, err := svc.Overview(context.Background(), domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(0), out.Devices.Total)
	require.Zero(t, out.Devices.OnlineRate)
	require.Empty(t, out.Abnormal)
	// recent tasks/runs initialize to empty slices (not nil) so the JSON keeps
	// rendering [], the dashboard skeleton-freeze lesson (#385) is pinned here
	require.NotNil(t, out.Scanning.RecentTasks)
	require.Empty(t, out.Scanning.RecentTasks)
	require.NotNil(t, out.Scanning.RecentRuns)
	require.Empty(t, out.Scanning.RecentRuns)
	require.Nil(t, out.Scanning.LastDiscovery)
}

func TestDashboardConfigCRUD_PositionAutoAssign(t *testing.T) {
	svc, _ := setupDashboardService(t)
	ctx := context.Background()

	// no position -> lands after all existing widgets (max+1)
	first, err := svc.CreateConfig(ctx, db.CreateDashboardConfigParams{
		Name: "online-gauge", Type: "gauge", DataSource: "builtin", Query: "",
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), first.Position)

	second, err := svc.CreateConfig(ctx, db.CreateDashboardConfigParams{
		Name: "types-pie", Type: "pie", DataSource: "builtin", RefreshInterval: 60,
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), second.Position)

	// explicit position is respected
	third, err := svc.CreateConfig(ctx, db.CreateDashboardConfigParams{
		Name: "pinned", Type: "line", DataSource: "builtin", Position: 10,
	})
	require.NoError(t, err)
	require.Equal(t, int64(10), third.Position)

	all, err := svc.ListConfigs(ctx)
	require.NoError(t, err)
	require.Len(t, all, 3)

	// update with position <= 0 falls back to max+1 (full-replace PUT)
	updated, err := svc.UpdateConfig(ctx, db.UpdateDashboardConfigParams{
		Name: "renamed", Type: "gauge", DataSource: "builtin", ID: first.ID,
	})
	require.NoError(t, err)
	require.Equal(t, int64(11), updated.Position)
	require.Equal(t, "renamed", updated.Name)

	require.NoError(t, svc.DeleteConfig(ctx, first.ID))
	err = svc.DeleteConfig(ctx, first.ID)
	require.ErrorContains(t, err, "not found")
}

func TestDashboardQuery_UnconfiguredDataSource(t *testing.T) {
	svc, _ := setupDashboardService(t)
	ctx := context.Background()

	_, err := svc.Query(ctx, "up", "")
	require.ErrorContains(t, err, "not configured")

	_, err = svc.QueryRange(ctx, "up", "0", "1", "15")
	require.ErrorContains(t, err, "not configured")
}

func TestDashboardQuery_ProxiesToDataSource(t *testing.T) {
	var gotPath, gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector"}}`)
	}))
	t.Cleanup(upstream.Close)

	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	cfg := &config.Config{}
	cfg.Dashboard.PrometheusURL = upstream.URL
	cfg.Dashboard.DataSourceType = "prometheus"
	svc := NewDashboardService(conn, cfg)

	body, err := svc.Query(context.Background(), "up", "1700000000")
	require.NoError(t, err)
	require.Contains(t, string(body), "vector")
	require.Equal(t, "/api/v1/query", gotPath)
	require.Contains(t, gotQuery, "query=up")
	require.Contains(t, gotQuery, "time=1700000000")

	body, err = svc.QueryRange(context.Background(), "up", "0", "100", "15")
	require.NoError(t, err)
	require.Contains(t, string(body), "vector")
	require.Equal(t, "/api/v1/query_range", gotPath)

	all, err := svc.ListConfigs(context.Background())
	require.NoError(t, err)
	require.Empty(t, all)
}

func TestDashboardQuery_UpstreamErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(upstream.Close)

	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	cfg := &config.Config{}
	cfg.Dashboard.PrometheusURL = upstream.URL
	svc := NewDashboardService(conn, cfg)

	_, err = svc.Query(context.Background(), "up", "")
	require.ErrorContains(t, err, "status 500")

	// unreachable upstream shows up as UpstreamError so handlers can map 502
	unreachable := &config.Config{}
	unreachable.Dashboard.PrometheusURL = "http://127.0.0.1:1"
	unreachableSvc := NewDashboardService(conn, unreachable)
	_, err = unreachableSvc.Query(context.Background(), "up", "")
	var upErr *UpstreamError
	require.ErrorAs(t, err, &upErr)
}
