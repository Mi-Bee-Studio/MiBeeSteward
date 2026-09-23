// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
)

// TestHeartbeatRunChecks_OfflineBackoffSkips drives the offline-backoff
// branch: a device already marked offline in the statusCache is skipped on
// non-boundary ticks, then probed again on the modulo boundary (where the
// refused TCP target also pins the transport-error branch of probeAndRecord).
func TestHeartbeatRunChecks_OfflineBackoffSkips(t *testing.T) {
	svc, dbConn, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	devID := insertTestDevice(t, queries, ctx, "backoff-dev", "127.0.0.1")
	cfg, err := queries.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
		DeviceID: devID, Method: "tcp", Target: "127.0.0.1:1",
		IntervalSeconds: 1, TimeoutSeconds: 1, Enabled: 1,
	})
	require.NoError(t, err)

	svc.cfg.OfflineBackoffTicks = 2
	svc.statusCacheMu.Lock()
	svc.statusCache[devID] = "offline"
	svc.statusCacheMu.Unlock()
	svc.tickCount = 0 // next tick lands on 1 → 1%2 != 0 → skip

	svc.runChecks(ctx)
	svc.lastProbeMu.RLock()
	_, probed := svc.lastProbe[cfg.ID]
	svc.lastProbeMu.RUnlock()
	require.False(t, probed, "offline device must be skipped on a non-boundary backoff tick")

	// Next tick lands on the boundary → the device IS probed (and the dead
	// port makes the probe itself error out, the failure-aggregation seam).
	svc.runChecks(ctx)
	svc.lastProbeMu.RLock()
	_, probed = svc.lastProbe[cfg.ID]
	svc.lastProbeMu.RUnlock()
	require.True(t, probed, "backoff boundary tick must probe the device")

	svc.statusCacheMu.RLock()
	st := svc.statusCache[devID]
	svc.statusCacheMu.RUnlock()
	require.NotEqual(t, "online", st, "a refused TCP target can never be online")
	require.NoError(t, dbConn.Close())
}

// TestHeartbeatRunChecks_EmptyConfigShortCircuit: with no enabled configs the
// tick is a cheap no-op (the probe loop body never runs).
func TestHeartbeatRunChecks_EmptyConfigShortCircuit(t *testing.T) {
	svc, _, _ := setupHeartbeatTest(t)
	before := svc.tickCount
	svc.runChecks(context.Background())
	require.Equal(t, before+1, svc.tickCount, "ticks advance even with nothing to probe")
}
