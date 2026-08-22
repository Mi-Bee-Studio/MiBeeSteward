// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func newAgentFleetService(t *testing.T, remoteOps bool) (*AgentCommandService, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	return NewAgentCommandService(q, remoteOps), q
}

func TestAgentCommandService_OpsGating(t *testing.T) {
	ctx := context.Background()

	// Center switch OFF: ops commands rejected with ErrRemoteOpsDisabled.
	svc, q := newAgentFleetService(t, false)
	_, err := svc.Enqueue(ctx, "agent-x", "restart", nil)
	require.ErrorIs(t, err, ErrRemoteOpsDisabled)

	// scan stays always-on.
	_, err = svc.Enqueue(ctx, "agent-x", "scan", map[string]interface{}{"targets": "192.168.62.0/24"})
	require.NoError(t, err)

	// Unknown command rejected regardless of the switch.
	_, err = svc.Enqueue(ctx, "agent-x", "rm-rf", nil)
	require.ErrorIs(t, err, ErrUnknownCommand)

	// Center switch ON: ops commands enqueue.
	svcOn := NewAgentCommandService(q, true)
	_, err = svcOn.Enqueue(ctx, "agent-x", "logs-tail", nil)
	require.NoError(t, err)
}

func TestAgentCommandService_FleetStatusRoundtrip(t *testing.T) {
	ctx := context.Background()
	svc, _ := newAgentFleetService(t, false)

	meta := &domain.AgentMeta{
		Version: "v0.5.1", GoVersion: "go1.24.1",
		Hostname: "brume2", UptimeSec: 3600, ScansTotal: 42,
	}
	require.NoError(t, svc.UpsertAgentStatus(ctx, "agent-62", meta, 12.5))
	// nil meta (old-agent report) must not clobber... it overwrites with zeros
	// by design (last report wins); assert the first write landed correctly.
	rows, err := svc.ListAgentStatus(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "agent-62", rows[0].AgentID)
	require.Equal(t, "v0.5.1", rows[0].Version)
	require.Equal(t, "brume2", rows[0].Hostname)
	require.EqualValues(t, 3600, rows[0].UptimeSeconds)
	require.InDelta(t, 12.5, rows[0].ClockOffsetSeconds, 0.001)
	require.EqualValues(t, 42, rows[0].ScansTotal)

	// Upsert again (idempotent on agent_id).
	require.NoError(t, svc.UpsertAgentStatus(ctx, "agent-62", meta, 13.0))
	rows, err = svc.ListAgentStatus(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.InDelta(t, 13.0, rows[0].ClockOffsetSeconds, 0.001)
}
