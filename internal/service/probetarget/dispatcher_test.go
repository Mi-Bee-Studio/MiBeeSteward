// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// fakeEnqueuer records probe plans per agent (test double for the command
// service slice).
type fakeEnqueuer struct {
	plans map[string][]map[string]interface{} // agentID → enqueued payloads
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, agentID, _ string, payload map[string]interface{}) (db.AgentCommand, error) {
	if f.plans == nil {
		f.plans = map[string][]map[string]interface{}{}
	}
	f.plans[agentID] = append(f.plans[agentID], payload)
	return db.AgentCommand{ID: int64(len(f.plans[agentID]))}, nil
}

func setupDispatch(t *testing.T) (*AgentDispatcher, *fakeEnqueuer, *db.Queries, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	fake := &fakeEnqueuer{}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewAgentDispatcher(queries, fake, quiet), fake, queries, conn
}

func seedVantageWorld(t *testing.T, conn *sql.DB) {
	t.Helper()
	ctx := context.Background()
	// One agent-bound network (agent-62) so 'all' plans have a destination.
	_, err := conn.ExecContext(ctx, `INSERT INTO networks (id, name, cidr, agent_id) VALUES (3, 'lan-62', '192.168.62.0/24', 'agent-62')`)
	require.NoError(t, err)
	mk := func(name, target, vantage string) {
		_, err := conn.ExecContext(ctx,
			`INSERT INTO probe_targets (name, module, target, vantage, interval_seconds, timeout_seconds, enabled)
			 VALUES (?, 'http', ?, ?, 60, 10, 1)`, name, target, vantage)
		require.NoError(t, err)
	}
	mk("center-only", "http://center.example/", domain.ProbeVantageCenter)
	mk("agent-only", "http://agent.example/", domain.ProbeVantageAgentPrefix+"agent-62")
	mk("both", "http://both.example/", domain.ProbeVantageAll)
}

// TestAgentDispatch_GroupsAndFingerprints pins the routing table: agent-only
// plans go to their agent, 'all' plans to every bound agent, center plans to
// nobody; and an unchanged plan is NOT re-enqueued on the next tick.
func TestAgentDispatch_GroupsAndFingerprints(t *testing.T) {
	d, fake, _, conn := setupDispatch(t)
	seedVantageWorld(t, conn)
	ctx := context.Background()

	d.DispatchTick(ctx)
	require.Len(t, fake.plans["agent-62"], 1, "one plan on first tick")
	plan := fake.plans["agent-62"][0]["targets"].([]Spec)
	require.Len(t, plan, 2, "agent-only + all, not the center-only target")
	names := map[string]bool{plan[0].Name: true, plan[1].Name: true}
	require.True(t, names["agent-only"] && names["both"])
	for _, spec := range plan {
		require.Equal(t, domain.ProbeVantageAgentPrefix+"agent-62", spec.Vantage,
			"'all' must be canonicalized to the receiving agent's track")
	}

	// Unchanged plan: second tick enqueues nothing.
	d.DispatchTick(ctx)
	require.Len(t, fake.plans["agent-62"], 1, "steady state must be zero command traffic")

	// Plan change (interval edit) re-ships exactly once more.
	_, err := conn.ExecContext(ctx, `UPDATE probe_targets SET interval_seconds = 120 WHERE name = 'both'`)
	require.NoError(t, err)
	d.DispatchTick(ctx)
	require.Len(t, fake.plans["agent-62"], 2)
	d.DispatchTick(ctx)
	require.Len(t, fake.plans["agent-62"], 2)
}

// TestAgentDispatch_ClearsEmptyPlan pins the empty-plan clear: when an
// agent's whole target set disappears it receives ONE final empty plan; an
// agent that never had targets receives nothing.
func TestAgentDispatch_ClearsEmptyPlan(t *testing.T) {
	d, fake, _, conn := setupDispatch(t)
	seedVantageWorld(t, conn)
	ctx := context.Background()

	d.DispatchTick(ctx)
	require.Len(t, fake.plans["agent-62"], 1)

	_, err := conn.ExecContext(ctx, `DELETE FROM probe_targets WHERE vantage != 'center'`)
	require.NoError(t, err)
	d.DispatchTick(ctx)
	require.Len(t, fake.plans["agent-62"], 2, "exactly one clearing plan")
	clearPlan := fake.plans["agent-62"][1]["targets"].([]Spec)
	require.Empty(t, clearPlan)
	d.DispatchTick(ctx)
	require.Len(t, fake.plans["agent-62"], 2, "no repeat clears")
}

// TestIngestAgentResults_OwnsVantage pins the ownership rule: whatever
// vantage the payload claims, rows are stored under the REPORTING agent's
// track; rows for deleted targets are skipped, not failed.
func TestIngestAgentResults_OwnsVantage(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(queries, quiet, nil)
	svc := New(queries, engine)
	ctx := context.Background()

	created, err := svc.Create(ctx, validCreate("http", "http://x.example/"))
	require.NoError(t, err)

	// Payload lies about the vantage; ingest stamps the agent's own track.
	n, err := svc.IngestAgentResults(ctx, "agent-62", []AgentResultReport{
		{TargetID: created.ID, Vantage: "center", Status: "success", LatencyMs: 12.5, CheckedAt: "2026-08-26T02:00:00Z"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, n)

	res, _, err := svc.Results(ctx, created.ID, "", 10, 0)
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, domain.ProbeVantageAgentPrefix+"agent-62", res[0].Vantage)
	require.Equal(t, "success", res[0].Status)

	// Unknown target id: skipped silently.
	n, err = svc.IngestAgentResults(ctx, "agent-62", []AgentResultReport{
		{TargetID: 9999, Status: "success", CheckedAt: "2026-08-26T02:01:00Z"},
	})
	require.NoError(t, err)
	require.Equal(t, 0, n)
}
