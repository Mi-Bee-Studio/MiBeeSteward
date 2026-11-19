// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// seedAgentStatus inserts one agent_status row via the raw table (the fleet
// upsert path is exercised elsewhere); agent_id must match a registered
// agent token for plan routing, but the sweep only reads the address.
func seedAgentStatus(t *testing.T, conn *db.Queries, agentID, ip string) {
	t.Helper()
	require.NoError(t, conn.UpsertAgentStatus(context.Background(), db.UpsertAgentStatusParams{
		AgentID: agentID, Version: "v-test", LastSourceIp: ip, LastReportAt: time.Now().UTC(),
	}))
}

func meshTargetsByName(t *testing.T, conn *db.Queries) map[string]db.ProbeTarget {
	t.Helper()
	targets, err := conn.ListProbeTargets(context.Background())
	require.NoError(t, err)
	out := map[string]db.ProbeTarget{}
	for _, tgt := range targets {
		if len(tgt.Name) > 5 && tgt.Name[:5] == "mesh-" {
			out[tgt.Name] = tgt
		}
	}
	return out
}

func newAutogenForMesh(t *testing.T) (*AutogenService, *db.Queries, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	on := true
	cfg := config.ProbeAutogenConfig{Enabled: true, IntervalSeconds: 120, MaxTargets: 500, MeshEnabled: &on}
	return NewAutogenService(queries, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))), queries, conn
}

// TestAutogenMesh pins the #747 matrix autogen: with two reporting agents the
// sweep creates center->agent and ordered agent->agent legs with the agent's
// report source address, source='system' (quality category), the burst
// option block, and the executing vantage; repeat sweeps converge; an agent
// that stops reporting parks its legs.
func TestAutogenMesh(t *testing.T) {
	svc, conn, rawConn := newAutogenForMesh(t)
	seedAgentStatus(t, conn, "agent-a", "192.0.2.11")
	seedAgentStatus(t, conn, "agent-b", "192.0.2.12")

	created, _, _, err := svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Equal(t, 4, created, "center->a, center->b, a->b, b->a = 4 mesh legs (no service rows in this fixture)")

	rows := meshTargetsByName(t, conn)
	require.Len(t, rows, 4)

	ca := rows["mesh-center-to-agent-a"]
	require.Equal(t, "192.0.2.11", ca.Target)
	require.Equal(t, domain.ProbeVantageCenter, ca.Vantage)
	require.Equal(t, "icmp", ca.Module)
	require.Equal(t, domain.ProbeSourceSystem, ca.Source)
	require.JSONEq(t, `{"burst_count":10}`, ca.Options)

	ab := rows["mesh-agent-a-to-agent-b"]
	require.Equal(t, "192.0.2.12", ab.Target)
	require.Equal(t, domain.ProbeVantageAgentPrefix+"agent-a", ab.Vantage, "the SOURCE agent executes")

	ba := rows["mesh-agent-b-to-agent-a"]
	require.Equal(t, "192.0.2.11", ba.Target)
	require.Equal(t, domain.ProbeVantageAgentPrefix+"agent-b", ba.Vantage)

	// Category: system source lands in quality (the matrix view's home).
	require.Equal(t, ProbeCategoryQuality, TargetCategory(ca))

	// Repeat sweep converges (no churn).
	created2, enabled2, disabled2, err := svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Zero(t, created2+enabled2+disabled2)

	// agent-b is DEREGISTERED (its agent_status row drops, same path the
	// agentwatch sweeper exercises): its legs park, agent-a's stay.
	require.NoError(t, conn.UpsertAgentStatus(context.Background(), db.UpsertAgentStatusParams{
		AgentID: "agent-a", Version: "v-test", LastSourceIp: "192.0.2.11", LastReportAt: time.Now().UTC(),
	}))
	_, err = rawConn.ExecContext(context.Background(), "DELETE FROM agent_status WHERE agent_id = ?", "agent-b")
	require.NoError(t, err)
	_, _, disabled3, err := svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Equal(t, 3, disabled3, "center->b, a->b, b->a park")
	rows = meshTargetsByName(t, conn)
	require.Len(t, rows, 4, "parked rows kept for history")
	require.EqualValues(t, 0, rows["mesh-center-to-agent-b"].Enabled)
	require.EqualValues(t, 1, rows["mesh-center-to-agent-a"].Enabled)

	// agent-b returns: legs re-enable.
	seedAgentStatus(t, conn, "agent-b", "192.0.2.12")
	_, enabled4, _, err := svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Equal(t, 3, enabled4)
}

// TestAutogenMeshDisabled pins the switch: mesh_enabled=false skips the
// matrix entirely (no rows created, none parked).
func TestAutogenMeshDisabled(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	off := false
	cfg := config.ProbeAutogenConfig{Enabled: true, IntervalSeconds: 120, MaxTargets: 500, MeshEnabled: &off}
	svc := NewAutogenService(queries, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	seedAgentStatus(t, queries, "agent-a", "192.0.2.11")
	_, _, _, err = svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Empty(t, meshTargetsByName(t, queries))
}

// TestAutogenMeshUnknownAddress: an agent whose source address is unknown
// (proxy chain) contributes no legs instead of a broken icmp target.
func TestAutogenMeshUnknownAddress(t *testing.T) {
	svc, conn, _ := newAutogenForMesh(t)
	seedAgentStatus(t, conn, "agent-a", "192.0.2.11")
	seedAgentStatus(t, conn, "agent-b", "")
	_, _, _, err := svc.Sweep(context.Background())
	require.NoError(t, err)
	rows := meshTargetsByName(t, conn)
	require.Len(t, rows, 1, "only the center->a leg")
	require.Contains(t, rows, "mesh-center-to-agent-a")
}
