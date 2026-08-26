// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package routes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// TestAgentForNetwork covers the dispatch decision helper: nil network,
// network without agent, agent-bound network, and a missing network row all
// resolve deterministically (missing → local scan, never a panic).
func TestAgentForNetwork(t *testing.T) {
	conn, err0 := testutil.SetupTestDBFromSchema()
	require.NoError(t, err0)
	t.Cleanup(func() { conn.Close() })
	_, err := conn.Exec(`INSERT INTO networks (id, name, cidr, agent_id) VALUES
		(1, 'lan-63', '192.168.63.0/24', NULL),
		(3, 'lan-62', '192.168.62.0/24', 'agent-62')`)
	require.NoError(t, err)

	require.Equal(t, "", agentForNetwork(conn, nil), "nil network must run locally")
	id1 := int64(1)
	require.Equal(t, "", agentForNetwork(conn, &id1), "agent-less network must run locally")
	id3 := int64(3)
	require.Equal(t, "agent-62", agentForNetwork(conn, &id3), "agent-bound network must dispatch")
	id9 := int64(999)
	require.Equal(t, "", agentForNetwork(conn, &id9), "missing network must fall back to local")
}

// TestDispatchAgentScan_SuccessAndFailure pins the agent-task dispatch
// behavior: a successful enqueue records a completed run row; a rejected
// enqueue (targets outside the agent network's CIDR) records a FAILED run
// with the reason — the failure must be visible in run history, not just logs.
func TestDispatchAgentScan_SuccessAndFailure(t *testing.T) {
	conn, err0 := testutil.SetupTestDBFromSchema()
	require.NoError(t, err0)
	t.Cleanup(func() { conn.Close() })
	_, err := conn.Exec(`INSERT INTO networks (id, name, cidr, agent_id) VALUES
		(3, 'lan-62', '192.168.62.0/24', 'agent-62')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO scan_tasks (id, name, targets, cron_expr, timeout, concurrent_hosts, enabled)
		VALUES (7, 'lan-62-agent', '192.168.62.0/24', '*/10 * * * *', 300, 8, 1)`)
	require.NoError(t, err)

	queries := db.New(conn)
	svc := service.NewAgentCommandService(queries, false, false)
	ctx := context.Background()

	// Success path: in-CIDR targets → command enqueued + completed run.
	dispatchAgentScan(ctx, queries, svc, 7, "192.168.62.0/24", 300*1e9, "agent-62")
	var cmdCount int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM agent_commands WHERE agent_id='agent-62' AND command='scan'`).Scan(&cmdCount))
	require.Equal(t, 1, cmdCount, "scan command must be enqueued for the agent")
	run, err := queries.GetLatestRun(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, "completed", run.Status)
	require.Equal(t, "", run.ErrorMessage)

	// Failure path: out-of-CIDR targets → no command + failed run with reason.
	dispatchAgentScan(ctx, queries, svc, 7, "10.99.0.0/24", 300*1e9, "agent-62")
	var cmdCount2 int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM agent_commands`).Scan(&cmdCount2))
	require.Equal(t, 1, cmdCount2, "rejected dispatch must not enqueue a second command")
	run2, err := queries.GetLatestRun(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, "failed", run2.Status)
	require.NotEmpty(t, run2.ErrorMessage, "failure reason must surface in the run row")
}
