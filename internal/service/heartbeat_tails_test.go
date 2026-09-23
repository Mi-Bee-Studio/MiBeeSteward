// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
)

// TestHeartbeatRunChecks_TailBranches sweeps the remaining runChecks /
// probeAndRecord / CreateConfigs guards: a dead handle fails the config
// listing (tick aborts), a negative backoff clamps to disabled, a
// recently-probed device is skipped as not-due, and a zero timeout defaults.
func TestHeartbeatRunChecks_TailBranches(t *testing.T) {
	svc, dbConn, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	// Negative backoff clamps to 0 (disabled) instead of panicking on the
	// modulo below; the empty-config tick completes.
	svc.cfg.OfflineBackoffTicks = -3
	svc.runChecks(ctx)

	// A live device + config: first tick probes (timeout<=0 branch takes the
	// default), stamps lastProbe; an immediate second tick skips it as
	// not-due (interval 3600s hasn't elapsed).
	devID := insertTestDevice(t, queries, ctx, "tail-hb", "127.0.0.1")
	cfgID, err := queries.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
		DeviceID: devID, Method: "tcp", Target: "127.0.0.1:1",
		IntervalSeconds: 3600, TimeoutSeconds: 0, Enabled: 1,
	})
	require.NoError(t, err)

	svc.cfg.OfflineBackoffTicks = 0
	svc.runChecks(ctx)
	svc.lastProbeMu.RLock()
	_, stamped := svc.lastProbe[cfgID.ID]
	svc.lastProbeMu.RUnlock()
	require.True(t, stamped, "first tick probes the never-probed config")

	before := svc.tickCount
	svc.runChecks(ctx) // not-due skip (the interval hasn't elapsed)
	require.Equal(t, before+1, svc.tickCount, "tick advances even when nothing is due")

	// CreateConfigs against a dead handle fails at the insert wrap after
	// validation passes.
	require.NoError(t, dbConn.Close())
	err = svc.CreateConfigs(ctx, devID, []scannerv2.HeartbeatSpec{
		{Method: "tcp", Target: "127.0.0.1:2", IntervalSeconds: 30, TimeoutSeconds: 5},
	})
	require.ErrorContains(t, err, "create tcp config")

	// runChecks over the dead handle aborts at the listing error branch.
	svc.runChecks(ctx)
}
