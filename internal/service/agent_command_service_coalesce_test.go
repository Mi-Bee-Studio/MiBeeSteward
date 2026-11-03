// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// setupCoalesceService builds the service over an in-memory DB with one
// network (10.99.0.0/16) bound to agent "coag-1" so scan target validation
// resolves a containing network.
func setupCoalesceService(t *testing.T) (*service.AgentCommandService, *sqldb.Queries) {
	t.Helper()
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })

	queries := sqldb.New(dbConn)
	cidr := "10.99.0.0/16"
	net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{
		Name: "lan-coag", Cidr: &cidr, Site: strPtrCoag("site-coag"),
	})
	require.NoError(t, err)
	require.NoError(t, queries.SetNetworkAgentID(context.Background(), sqldb.SetNetworkAgentIDParams{
		AgentID: strPtrCoag("coag-1"), ID: net.ID,
	}))
	return service.NewAgentCommandService(queries, false, false), queries
}

func strPtrCoag(s string) *string { return &s }

// A probe plan is a full snapshot: while an agent is offline the dispatcher
// re-sends a plan every tick, and each resend must supersede (not queue
// behind) the still-pending one. This is the bound that keeps a day-long
// outage from burying the agent in hundreds of stale plans.
func TestEnqueueProbePlanSupersedesPending(t *testing.T) {
	svc, queries := setupCoalesceService(t)
	ctx := context.Background()

	first, err := svc.Enqueue(ctx, "coag-1", "probe", map[string]interface{}{"targets": []string{"a"}})
	require.NoError(t, err)
	for i := 0; i < 50; i++ { // a long offline stretch of ticks
		_, err = svc.Enqueue(ctx, "coag-1", "probe", map[string]interface{}{"targets": []string{"b"}})
		require.NoError(t, err)
	}

	total, err := queries.CountAgentCommands(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, total, "every newer plan must replace the pending one")

	pending, err := queries.ListPendingAgentCommands(ctx, sqldb.ListPendingAgentCommandsParams{
		AgentID: "coag-1", Limit: 10,
	})
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NotEqual(t, first.ID, pending[0].ID, "the surviving row is the NEWEST plan")
	require.Contains(t, pending[0].Payload, "\"b\"")
}

// The scheduler re-dispatches the same scan every tick while the agent is
// offline; an identical pending scan must coalesce to the existing row
// (same payload bytes — json.Marshal sorts map keys), while a DIFFERENT scan
// (another task/target set) still gets its own row.
func TestEnqueueScanDedupesIdenticalPayload(t *testing.T) {
	svc, queries := setupCoalesceService(t)
	ctx := context.Background()

	scan := map[string]interface{}{"targets": "10.99.1.0/24", "timeout": 30}
	a, err := svc.Enqueue(ctx, "coag-1", "scan", scan)
	require.NoError(t, err)
	for i := 0; i < 50; i++ {
		b, err := svc.Enqueue(ctx, "coag-1", "scan", scan)
		require.NoError(t, err)
		require.Equal(t, a.ID, b.ID, "identical pending scan must return the existing row")
	}

	// A different task (different targets) is independent work, not a duplicate.
	_, err = svc.Enqueue(ctx, "coag-1", "scan", map[string]interface{}{"targets": "10.99.2.7", "timeout": 30})
	require.NoError(t, err)

	total, err := queries.CountAgentCommands(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 2, total, "identical scans collapse to one; a different scan coexists")
}

// End-to-end shape of the incident that motivated the guard: an agent goes
// offline for many scheduler ticks (scan + probe every tick), comes back —
// the pending queue it faces must be bounded (one scan + one plan), not the
// hundreds of rows observed in the field.
func TestEnqueueOfflineStretchesStayBounded(t *testing.T) {
	svc, queries := setupCoalesceService(t)
	ctx := context.Background()

	for tick := 0; tick < 100; tick++ {
		_, err := svc.Enqueue(ctx, "coag-1", "scan", map[string]interface{}{"targets": "10.99.1.0/24", "timeout": 30})
		require.NoError(t, err)
		_, err = svc.Enqueue(ctx, "coag-1", "probe", map[string]interface{}{"plan": tick})
		require.NoError(t, err)
	}

	total, err := queries.CountAgentCommands(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 2, total, "100 offline ticks must leave one pending scan + one pending plan")
}
