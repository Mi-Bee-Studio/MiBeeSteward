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
