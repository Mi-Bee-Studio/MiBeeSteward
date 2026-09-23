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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/dbopen"
	"mibee-steward/internal/service/scannerv2/cleanup"
	"mibee-steward/internal/service/scannerv2/reconcile"
	"mibee-steward/internal/testutil"
)

// TestHeartbeatStore_FinalDrainCommitsBufferedRows is the regression test for
// the shutdown data-loss bug: the final drain used to commit under the ALREADY
// CANCELLED loop context (the fresh 5s ctx it built was never passed in), so
// every row still buffered at Close was dropped with a "context canceled"
// error. Enqueue rows and Close immediately, well before the 5s flush ticker
// - then verify the rows landed.
func TestHeartbeatStore_FinalDrainCommitsBufferedRows(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenHeartbeatStore(filepath.Join(dir, "hb.db"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	store.Start(ctx)

	for i := 0; i < 5; i++ {
		store.Enqueue(resultRow{
			DeviceID: int64(i + 1), ConfigID: 1, Status: "success",
			LatencyMs: 12.5, CheckedAt: time.Now().UTC(),
		})
		store.EnqueueLiveness(livenessRow{
			DeviceID: int64(i + 1), Status: "online", Source: "heartbeat",
			CheckedAt: time.Now().UTC(),
		})
	}

	// Close immediately, the ticker (5s) has NOT fired, so everything is
	// still buffered; only the final drain can commit it.
	done := make(chan error, 1)
	go func() { done <- store.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(8 * time.Second):
		t.Fatal("Close did not finish (final drain hung)")
	}
	cancel()

	// Close() also closes the store's DB handle, read the file back through
	// a fresh connection to verify what the final drain actually committed.
	verify, err := dbopen.Open(filepath.Join(dir, "hb.db"), "journal_mode=WAL", "busy_timeout=5000")
	require.NoError(t, err)
	t.Cleanup(func() { verify.Close() })
	var results, liveness int
	require.NoError(t, verify.QueryRow(`SELECT COUNT(*) FROM heartbeat_results`).Scan(&results))
	require.NoError(t, verify.QueryRow(`SELECT COUNT(*) FROM device_liveness`).Scan(&liveness))
	require.Equal(t, 5, results, "all buffered heartbeat_results must survive shutdown")
	require.Equal(t, 5, liveness, "all buffered liveness samples must survive shutdown")
}

// TestTokenBlacklist_LazyExpiry pins the goroutine-free expiry semantics: a
// live entry reports blacklisted, an expired entry reports clean AND is
// deleted on sight (the map self-cleans under traffic).
func TestTokenBlacklist_LazyExpiry(t *testing.T) {
	b := NewTokenBlacklist()

	b.Add("live-jti", time.Hour)
	require.True(t, b.IsBlacklisted("live-jti"))
	require.False(t, b.IsBlacklisted("never-added"))

	// Already-expired TTL → clean on first read, and gone from the map.
	b.Add("dead-jti", -time.Minute)
	require.False(t, b.IsBlacklisted("dead-jti"))
	require.False(t, b.IsBlacklisted("dead-jti"), "expired entry must be deleted on sight")
}

// TestStopWithoutStartDoesNotHang pins the lifecycle contract that a Stop()
// before Start() returns instead of blocking forever on a done channel no
// loop will ever close.
func TestStopWithoutStartDoesNotHang(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	instances := []interface{ Stop() }{
		reconcile.New(conn, time.Minute, nil, nil),
		cleanup.New(nil, nil, conn, conn, config.RetentionConfig{}),
	}
	for _, inst := range instances {
		done := make(chan struct{})
		go func(s interface{ Stop() }) {
			s.Stop()
			close(done)
		}(inst)
		select {
		case <-done:
			// returned immediately, correct
		case <-time.After(3 * time.Second):
			t.Fatal("Stop() before Start() hung")
		}
	}
}
