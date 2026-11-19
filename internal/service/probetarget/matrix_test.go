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
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// matrixWorld seeds a fleet of agents with report source addresses and the
// mesh-* legs an autogen sweep would have created for them.
func matrixWorld(t *testing.T, agents map[string]string) (*QualityService, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewQualityService(queries, testQualityConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	for id, ip := range agents {
		require.NoError(t, queries.UpsertAgentStatus(context.Background(), db.UpsertAgentStatusParams{
			AgentID: id, Version: "v-test", LastSourceIp: ip, LastReportAt: time.Now().UTC(),
		}))
	}
	return svc, queries
}

// meshLeg inserts one mesh-* leg the way the autogen sweep does.
func meshLeg(t *testing.T, queries *db.Queries, name, vantage, ip string, enabled int64) db.ProbeTarget {
	t.Helper()
	row, err := queries.CreateProbeTarget(context.Background(), db.CreateProbeTargetParams{
		Name: name, Module: "icmp", Target: ip,
		IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: enabled,
		Vantage: vantage, Options: meshOptionsJSON, Source: domain.ProbeSourceSystem,
	})
	require.NoError(t, err)
	return row
}

// seedLegRows appends n successes with the given latency/loss/jitter.
func seedLegRows(t *testing.T, queries *db.Queries, targetID int64, vantage string, n int, latency, loss, jitter float64) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, queries.CreateProbeResult(context.Background(), db.CreateProbeResultParams{
			TargetID: targetID, Status: "success", LatencyMs: latency,
			CheckedAt: time.Now().UTC().Add(-time.Duration(i) * time.Minute).Format(time.RFC3339),
			Vantage:   vantage, LossPct: loss, JitterMs: jitter,
		}))
	}
}

// TestBuildMatrix pins the N×N shape: axes are center-first then agents
// alphabetically, cells carry the window aggregate of the matching leg, and
// the diagonal is never emitted.
func TestBuildMatrix(t *testing.T) {
	svc, queries := matrixWorld(t, map[string]string{
		"agent-b": "192.0.2.20",
		"agent-a": "192.0.2.10",
	})

	legs := []struct {
		name, vantage, ip string
	}{
		{"mesh-center-to-agent-a", domain.ProbeVantageCenter, "192.0.2.10"},
		{"mesh-center-to-agent-b", domain.ProbeVantageCenter, "192.0.2.20"},
		{"mesh-agent-a-to-agent-b", "agent:agent-a", "192.0.2.20"},
		{"mesh-agent-b-to-agent-a", "agent:agent-b", "192.0.2.10"},
	}
	ids := map[string]int64{}
	for _, l := range legs {
		row := meshLeg(t, queries, l.name, l.vantage, l.ip, 1)
		ids[l.name] = row.ID
	}
	seedLegRows(t, queries, ids["mesh-center-to-agent-a"], domain.ProbeVantageCenter, 3, 12, 0, 1)
	seedLegRows(t, queries, ids["mesh-agent-a-to-agent-b"], "agent:agent-a", 2, 40, 10, 35)

	m, err := svc.BuildMatrix(context.Background(), 15)
	require.NoError(t, err)
	require.Equal(t, 15, m.WindowMinutes)
	require.NotEmpty(t, m.GeneratedAt)

	// Axes: center first, then agents alphabetically by node id.
	require.Len(t, m.Sources, 3)
	require.Equal(t, domain.ProbeVantageCenter, m.Sources[0].ID)
	require.Equal(t, "agent:agent-a", m.Sources[1].ID)
	require.Equal(t, "agent:agent-b", m.Sources[2].ID)
	require.Equal(t, m.Sources, m.Destinations)

	require.Len(t, m.Cells, len(legs))
	byPair := map[string]MatrixCell{}
	for _, c := range m.Cells {
		byPair[c.Source+"|"+c.Destination] = c
		require.NotEqual(t, c.Source, c.Destination, "no diagonal cells")
	}

	fast := byPair["center|agent:agent-a"]
	require.Equal(t, 3, fast.Samples)
	require.InDelta(t, 1.0, fast.OkRate, 1e-9)
	require.InDelta(t, 12.0, fast.P50Ms, 1e-9)
	require.Equal(t, "192.0.2.10", fast.Target)
	require.True(t, fast.Enabled)

	lossy := byPair["agent:agent-a|agent:agent-b"]
	require.Equal(t, 2, lossy.Samples)
	require.InDelta(t, 10.0, lossy.LossPct, 1e-9)
	require.InDelta(t, 35.0, lossy.JitterMs, 1e-9)

	// A leg with no rows in the window is still a cell (axis pair exists),
	// but carries Samples == 0 so the UI can render "not reported".
	idle := byPair["agent:agent-b|agent:agent-a"]
	require.Zero(t, idle.Samples)
}

// TestBuildMatrixSkipsDeregisteredDestination: a leg whose destination agent
// is no longer in the fleet has no axis entry. It must be dropped, not
// attributed to a phantom column.
func TestBuildMatrixSkipsDeregisteredDestination(t *testing.T) {
	svc, queries := matrixWorld(t, map[string]string{"agent-a": "192.0.2.10"})
	meshLeg(t, queries, "mesh-center-to-agent-a", domain.ProbeVantageCenter, "192.0.2.10", 1)
	meshLeg(t, queries, "mesh-center-to-agent-gone", domain.ProbeVantageCenter, "192.0.2.99", 0)

	m, err := svc.BuildMatrix(context.Background(), 15)
	require.NoError(t, err)
	require.Len(t, m.Cells, 1)
	require.Equal(t, "agent:agent-a", m.Cells[0].Destination)
	for _, d := range m.Destinations {
		require.NotEqual(t, "agent:agent-gone", d.ID, "deregistered agent must not appear")
	}
}

// TestBuildMatrixIgnoresNonMeshTargets: user targets share the table but not
// the prefix; only mesh-* legs belong in the grid.
func TestBuildMatrixIgnoresNonMeshTargets(t *testing.T) {
	svc, queries := matrixWorld(t, map[string]string{"agent-a": "192.0.2.10"})
	userTarget, err := queries.CreateProbeTarget(context.Background(), db.CreateProbeTargetParams{
		Name: "my-own-site", Module: "http", Target: "https://example.com",
		IntervalSeconds: 300, TimeoutSeconds: 10, Enabled: 1,
		Vantage: domain.ProbeVantageCenter, Source: "manual",
	})
	require.NoError(t, err)
	seedLegRows(t, queries, userTarget.ID, domain.ProbeVantageCenter, 2, 100, 0, 0)

	m, err := svc.BuildMatrix(context.Background(), 15)
	require.NoError(t, err)
	require.Empty(t, m.Cells)
	// Still one axis (center), so the UI shows its empty state rather than a
	// blank grid.
	require.Len(t, m.Sources, 1)
}

// TestBuildMatrixEmptyFleet: nothing registered at all is not an error.
func TestBuildMatrixEmptyFleet(t *testing.T) {
	svc, _ := setupQualityCfg(t, testQualityConfig())
	m, err := svc.BuildMatrix(context.Background(), 15)
	require.NoError(t, err)
	require.Empty(t, m.Cells)
	require.Len(t, m.Sources, 1)
	require.Equal(t, domain.ProbeVantageCenter, m.Sources[0].ID)
}
