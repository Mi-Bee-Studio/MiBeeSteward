// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package cleanup

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service/probe"
	"mibee-steward/internal/service/probeext"
	"mibee-steward/internal/testutil"
)

// TestPruneProbeExt pins the probe_ext.db retention sweep (#716/#718/#719 +
// #717 phases): rows older than the window disappear from ALL tables, fresh
// rows stay.
func TestPruneProbeExt(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)
	store, err := probeext.OpenStore(filepath.Join(t.TempDir(), "probe_ext.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()

	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	fresh := time.Now().UTC().Format(time.RFC3339)
	if err := store.InsertEgressRound(ctx, []probeext.EgressRow{
		{Vantage: "center", RoundAt: old, Source: "s1", Kind: "http", OK: true, IP: "93.184.216.1"},
		{Vantage: "center", RoundAt: fresh, Source: "s2", Kind: "http", OK: true, IP: "93.184.216.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertPathSample(ctx, probeext.PathSample{TargetID: 1, Vantage: "center", Method: "tcp", EndState: "reached", TracedAt: old}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertPathSample(ctx, probeext.PathSample{TargetID: 2, Vantage: "center", Method: "tcp", EndState: "reached", TracedAt: fresh}); err != nil {
		t.Fatal(err)
	}
	require.NoError(t, store.StorePhase(ctx, 1, "http", "center", old, 50, &probe.Phases{ResolvedIP: "93.184.216.3", ConnectMs: 20}))
	require.NoError(t, store.StorePhase(ctx, 2, "http", "center", fresh, 51, &probe.Phases{ResolvedIP: "93.184.216.4", ConnectMs: 21}))

	svc := New(queries, nil, nil, nil, store.Conn(), config.RetentionConfig{ProbeExtDays: 1})
	svc.pruneProbeExt(ctx)

	var rounds int
	if err := store.Conn().QueryRowContext(ctx, `SELECT count(*) FROM egress_rounds`).Scan(&rounds); err != nil {
		t.Fatal(err)
	}
	if rounds != 1 {
		t.Fatalf("egress_rounds left %d, want only the fresh round", rounds)
	}
	var samples int
	if err := store.Conn().QueryRowContext(ctx, `SELECT count(*) FROM path_samples`).Scan(&samples); err != nil {
		t.Fatal(err)
	}
	if samples != 1 {
		t.Fatalf("path_samples left %d, want only the fresh sample", samples)
	}
	var phases int
	if err := store.Conn().QueryRowContext(ctx, `SELECT count(*) FROM probe_phases`).Scan(&phases); err != nil {
		t.Fatal(err)
	}
	if phases != 1 {
		t.Fatalf("probe_phases left %d, want only the fresh row", phases)
	}
}

// TestPruneProbeExtZeroDays pins the disabled window guard.
func TestPruneProbeExtZeroDays(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)
	store, err := probeext.OpenStore(filepath.Join(t.TempDir(), "probe_ext.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	require.NoError(t, store.InsertEgressRound(ctx, []probeext.EgressRow{
		{Vantage: "center", RoundAt: "2020-01-01T00:00:00Z", Source: "s", Kind: "http", OK: true},
	}))
	svc := New(queries, nil, nil, nil, store.Conn(), config.RetentionConfig{})
	svc.pruneProbeExt(ctx) // days<=0: nothing deleted
	var n int
	if err := store.Conn().QueryRowContext(ctx, `SELECT count(*) FROM egress_rounds`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("zero-day guard deleted rows: %d", n)
	}
}
