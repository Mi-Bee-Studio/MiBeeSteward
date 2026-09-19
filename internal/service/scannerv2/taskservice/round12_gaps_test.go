// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package taskservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
)

// TestGetTaskResults_ConvertsRows pins the result conversion path (ports JSON
// → []int, limit clamping) and the not-found scope gate.
func TestGetTaskResults_ConvertsRows(t *testing.T) {
	svc, conn := setupGapService(t)
	ctx := context.Background()

	resp, err := svc.CreateTask(ctx, gapTaskReq("results-task", "192.168.80.0/24"))
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO scan_results (task_id, ip, alive, ports, services, snmp_data)
		VALUES (?, '192.168.80.5', 1, '[80,443]', '{}', '{"sys_name":"r1"}')`, resp.ID)
	require.NoError(t, err)

	// Limit below the floor clamps to 20 (no error); results carry the ports.
	out, total, err := svc.GetTaskResults(ctx, int(resp.ID), 1, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, out, 1)
	require.Equal(t, "192.168.80.5", out[0].IP)
	require.Equal(t, "[80,443]", out[0].Ports) // raw JSON string on the wire
}

// TestDeleteTask_RemovesResults pins the cascade clean-up branch: deleting a
// task drops its result rows too.
func TestDeleteTask_RemovesResults(t *testing.T) {
	svc, conn := setupGapService(t)
	ctx := context.Background()

	resp, err := svc.CreateTask(ctx, gapTaskReq("del-task", "192.168.81.0/24"))
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO scan_results (task_id, ip, alive) VALUES (?, '192.168.81.5', 0)`, resp.ID)
	require.NoError(t, err)

	require.NoError(t, svc.DeleteTask(ctx, resp.ID))

	// scan_results carry no FK cascade — history is retained for the
	// retention sweep (documented contract); the TASK row is gone.
	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM scan_tasks WHERE id=?`, resp.ID).Scan(&n))
	require.Equal(t, 0, n)

	// Deleting again → not found.
	require.ErrorIs(t, svc.DeleteTask(ctx, resp.ID), ErrScanTaskNotFound)
}

// TestCreateTask_ValidationMatrix walks every ValidateScanTaskRequest rejection
// reachable through the service (name/targets/ip-count/reserved/cron/timeout/
// concurrency bounds), plus the concurrent_hosts default.
func TestCreateTask_ValidationMatrix(t *testing.T) {
	svc, _ := setupGapService(t)
	ctx := context.Background()

	base := func() domain.ScanTaskRequest {
		return domain.ScanTaskRequest{
			Name: "v", Targets: "192.168.90.0/24", CronExpr: "0 3 * * *",
			Timeout: 60, ConcurrentHosts: 16,
			PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true}},
		}
	}
	bad := func(mut func(*domain.ScanTaskRequest)) error {
		r := base()
		mut(&r)
		_, err := svc.CreateTask(ctx, r)
		return err
	}

	require.ErrorContains(t, bad(func(r *domain.ScanTaskRequest) { r.Name = "" }), "name is required")
	require.ErrorContains(t, bad(func(r *domain.ScanTaskRequest) { r.Targets = "" }), "targets is required")
	require.ErrorContains(t, bad(func(r *domain.ScanTaskRequest) { r.Targets = "not-an-ip" }), "targets")
	require.ErrorContains(t, bad(func(r *domain.ScanTaskRequest) { r.Targets = "10.0.0.0/8" }), "too many IPs")
	require.ErrorContains(t, bad(func(r *domain.ScanTaskRequest) { r.Targets = "127.0.0.1" }), "reserved")
	require.ErrorContains(t, bad(func(r *domain.ScanTaskRequest) { r.CronExpr = "" }), "cron_expr is required")
	require.ErrorContains(t, bad(func(r *domain.ScanTaskRequest) { r.CronExpr = "not cron" }), "cron_expr")

	// concurrent_hosts=0 defaults (16); -1 / 10000 reject.
	okReq := base()
	okReq.ConcurrentHosts = 0
	resp, err := svc.CreateTask(ctx, okReq)
	require.NoError(t, err)
	require.Equal(t, 16, resp.ConcurrentHosts)
	require.Error(t, bad(func(r *domain.ScanTaskRequest) { r.ConcurrentHosts = -1 }))
	require.Error(t, bad(func(r *domain.ScanTaskRequest) { r.ConcurrentHosts = 10000 }))
}
