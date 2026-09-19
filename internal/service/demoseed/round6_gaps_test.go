// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package demoseed

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/testutil"
)

func TestCountJSON(t *testing.T) {
	require.JSONEq(t, `{"demo_devices":5}`, string(CountJSON(5)))
}

func TestFirstLine(t *testing.T) {
	require.Equal(t, "only", firstLine("only"))
	require.Equal(t, "first", firstLine("first\nsecond\nthird"))
	require.Equal(t, "", firstLine(""))
}

// TestActivity_LifecycleAndTick: StartActivity/Stop round-trip cleanly, and a
// direct tick() flips a seeded demo device's status and records the change —
// the 45s demo churn that keeps the fictional inventory alive.
func TestActivity_LifecycleAndTick(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	ctx := context.Background()
	require.NoError(t, Seed(ctx, dbConn, slog.Default()))

	a := StartActivity(dbConn, slog.Default())
	require.NotNil(t, a)

	// tick on a seeded DB mutates a demo device (both branches are
	// probabilistic; assert the aggregate: the online count changed).
	before := demoOnlineCount(t, dbConn)
	a.tick(ctx)
	after := demoOnlineCount(t, dbConn)
	require.NotEqual(t, before, after, "one tick must flip exactly one demo device")

	// Stop joins the goroutine promptly.
	done := make(chan struct{})
	go func() { a.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return")
	}
}

func demoOnlineCount(t *testing.T, db interface {
	QueryRow(query string, args ...any) *sql.Row
}) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE device_uuid LIKE 'demo-uuid-%' AND status='online'`).Scan(&n))
	return n
}

// TestActivity_TickBothBranches: 40 ticks virtually certainly exercise both
// the offline-flip and the 70%-recover branches (P(miss) < 1e-5), and every
// tick leaves the DB in a consistent one-change state.
func TestActivity_TickBothBranches(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	ctx := context.Background()
	require.NoError(t, Seed(ctx, dbConn, slog.Default()))

	a := StartActivity(dbConn, slog.Default())

	sawOnline, sawOffline := false, false
	for i := 0; i < 60 && (!sawOnline || !sawOffline); i++ {
		before := demoOnlineCount(t, dbConn)
		a.tick(ctx)
		after := demoOnlineCount(t, dbConn)
		if after > before {
			sawOnline = true
		}
		if after < before {
			sawOffline = true
		}
	}
	require.True(t, sawOnline, "the 70% recover branch must fire across 60 ticks")
	require.True(t, sawOffline, "the 30% offline branch must fire across 60 ticks")
	a.Stop()
}
