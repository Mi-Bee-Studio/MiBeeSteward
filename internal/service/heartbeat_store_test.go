// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// openTestStore opens a HeartbeatStore on a temp file (a real file, not :memory:,
// because the flush goroutine + WAL pragmas need a persistent backing store).
// Returns the store and its db path. The caller defers Close.
func openTestStore(t *testing.T) (*HeartbeatStore, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "heartbeat.db")
	store, err := OpenHeartbeatStore(dbPath)
	require.NoError(t, err)
	return store, dbPath
}

// waitForFlush blocks until device_liveness has at least minCount rows for ANY
// device, polling the table directly. The flush goroutine commits on a 5s timer
// (or when the buffer fills at 200), so this waits up to 8s for a small batch.
func waitForFlush(t *testing.T, store *HeartbeatStore, minCount int64) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var n int64
		err := store.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM device_liveness").Scan(&n)
		if err == nil && n >= minCount {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d liveness rows to flush", minCount)
}

// TestHeartbeatStore_DeviceLiveness_WriteQueryCycle verifies the device_liveness
// write→query round-trip: verdict samples enqueued via EnqueueLiveness are
// flushed to the table and readable via OnlineRatio / OfflineDuration /
// LivenessHistory. This guards the two time-format pain points: (1) samples are
// written as RFC3339 strings (the modernc monotonic-suffix workaround), so the
// queries must compare against them correctly; (2) GetLastOnlineAt returns a
// time.Time scanned back from that RFC3339 string — it must parse cleanly.
func TestHeartbeatStore_DeviceLiveness_WriteQueryCycle(t *testing.T) {
	store, dbPath := openTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Enqueue a mix of online/offline samples for device 1: 4 online then 2
	// offline (ratio 4/6 ≈ 0.667), with the last online ~20s ago.
	now := time.Now()
	checkedAt := []time.Time{
		now.Add(-60 * time.Second), // online
		now.Add(-50 * time.Second), // online
		now.Add(-40 * time.Second), // online
		now.Add(-20 * time.Second), // online  ← last online
		now.Add(-15 * time.Second), // offline
		now.Add(-10 * time.Second), // offline (newest)
	}
	for i, t := range checkedAt {
		status := "online"
		if i >= 4 {
			status = "offline"
		}
		store.EnqueueLiveness(livenessRow{
			DeviceID: 1, Status: status, Source: "heartbeat", CheckedAt: t,
		})
	}
	store.Start(context.Background())
	// Wait for the flush (5s interval) or force it via Close-then-reopen pattern:
	// simplest is to flush by stopping+reopening. Instead, poll until data appears.
	waitForFlush(t, store, 1)

	// OnlineRatio over a wide window (1h) should be 4/6 ≈ 0.667.
	ratio, count, err := store.OnlineRatio(ctx, 1, time.Hour)
	require.NoError(t, err)
	require.Equal(t, int64(6), count, "all 6 samples in the window")
	require.InDelta(t, 4.0/6.0, ratio, 0.01, "4 online of 6 samples")

	// OfflineDuration: most recent online sample was at now-20s. The device has
	// been "continuously offline" for ~20s + the flush delay. Wide slack covers
	// the 5s flush wait and scheduling jitter.
	dur, ok, err := store.OfflineDuration(ctx, 1)
	require.NoError(t, err)
	require.True(t, ok, "device 1 was seen online")
	require.InDelta(t, 20.0, dur.Seconds(), 20.0, "offline since the last online sample (~20s)")

	// LivenessHistory returns all samples newest-first.
	hist, err := store.LivenessHistory(ctx, 1, now.Add(-time.Hour), now.Add(time.Hour), 100)
	require.NoError(t, err)
	require.Len(t, hist, 6, "all 6 samples in history")
	require.Equal(t, "offline", hist[0].Status, "newest sample first (offline)")
	require.Equal(t, "online", hist[5].Status, "oldest sample last (online)")

	_ = dbPath // keep the temp dir referenced
}

// TestHeartbeatStore_DeviceLiveness_RetentionSweep verifies the batched retention
// delete works against RFC3339-stored rows: old samples are pruned, recent ones
// survive. This guards the time.Time-cutoff vs RFC3339-string comparison hazard.
func TestHeartbeatStore_DeviceLiveness_RetentionSweep(t *testing.T) {
	store, _ := openTestStore(t)
	defer store.Close()
	ctx := context.Background()

	now := time.Now()
	// Old samples (10 days ago) — past a 7-day cutoff.
	for i := 0; i < 3; i++ {
		store.EnqueueLiveness(livenessRow{
			DeviceID: 2, Status: "online", Source: "heartbeat",
			CheckedAt: now.AddDate(0, 0, -10),
		})
	}
	// Recent samples (1 hour ago) — within the cutoff.
	for i := 0; i < 2; i++ {
		store.EnqueueLiveness(livenessRow{
			DeviceID: 2, Status: "online", Source: "heartbeat",
			CheckedAt: now.Add(-time.Hour),
		})
	}
	store.Start(context.Background())
	waitForFlush(t, store, 5)

	// 7-day cutoff: prune everything older than 7 days. Use the SAME RFC3339
	// formatting the production cleanup.pruneDeviceLiveness uses (sqlc's
	// time.Time arg would compare wrong against stored RFC3339 text).
	cutoff := now.AddDate(0, 0, -7).UTC().Format(time.RFC3339)
	res, err := store.DB().ExecContext(ctx,
		`DELETE FROM device_liveness WHERE rowid IN (
			SELECT rowid FROM device_liveness WHERE checked_at < ? LIMIT 5000)`, cutoff)
	require.NoError(t, err)
	deleted, err := res.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(3), deleted, "the 3 ten-day-old samples pruned")

	// Recent samples survive.
	hist, err := store.LivenessHistory(ctx, 2, now.Add(-time.Hour*2), now, 100)
	require.NoError(t, err)
	require.Len(t, hist, 2, "recent samples survive the sweep")
}

// TestHeartbeatStore_LastOnlineAt verifies the "last confirmed alive" lookup:
// the most recent 'online' verdict timestamp. nil when never online; the
// timestamp itself (not a duration) when online samples exist.
func TestHeartbeatStore_LastOnlineAt(t *testing.T) {
	store, _ := openTestStore(t)
	defer store.Close()
	ctx := context.Background()

	// Device never seen online → nil, nil.
	last, err := store.LastOnlineAt(ctx, 999)
	require.NoError(t, err)
	require.Nil(t, last, "never-online device returns nil")

	// Seed: online at -60s, online at -20s (← last online), offline at -10s.
	now := time.Now().UTC()
	for i, s := range []struct {
		status string
		at     time.Duration
	}{
		{"online", -60 * time.Second},
		{"online", -20 * time.Second},
		{"offline", -10 * time.Second},
	} {
		store.EnqueueLiveness(livenessRow{
			DeviceID: 42, Status: s.status, Source: "heartbeat", CheckedAt: now.Add(s.at),
		})
		_ = i
	}
	store.Start(context.Background())
	waitForFlush(t, store, 3) // 3 samples seeded

	last, err = store.LastOnlineAt(ctx, 42)
	require.NoError(t, err)
	require.NotNil(t, last, "device with online samples returns a timestamp")
	// Must be the -20s sample, NOT the newer -10s offline one.
	require.WithinDuration(t, now.Add(-20*time.Second), *last, 2*time.Second,
		"LastOnlineAt is the most recent ONLINE sample, ignoring later offline ones")
}
