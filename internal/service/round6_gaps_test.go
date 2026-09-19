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
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// --- heartbeat: the device-aggregated check loop (runChecks path) ---

// TestHeartbeatService_RunChecks_OnlineVerdict covers the full per-tick loop:
// due configs are grouped by device, probed (a live local HTTP target), the
// result row + liveness sample land in the batched store, and the OR-verdict
// flips the device online in the status cache.
func TestHeartbeatService_RunChecks_OnlineVerdict(t *testing.T) {
	// Custom harness: a REAL store whose flush loop is NOT started — the
	// loop hot-drains the enqueue channels, so an unstarted store keeps the
	// rows observable in the buffers (deterministic; no 5s flush wait).
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	hbStore, err := OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb_gap.db"))
	require.NoError(t, err)
	t.Cleanup(func() { hbStore.Close() })
	cfg := &config.Config{Heartbeat: config.HeartbeatConfig{DefaultInterval: 60, Timeout: 5, RetentionDays: 30}}
	svc := NewHeartbeatService(dbConn, hbStore, cfg)
	svc.initStatusCache(context.Background())
	queries := sqldb.New(dbConn)
	ctx := context.Background()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)

	devID := insertTestDevice(t, queries, ctx, "alive-host", "127.0.0.1")
	_, err2 := queries.CreateHeartbeatConfig(ctx, sqldb.CreateHeartbeatConfigParams{
		DeviceID: devID, Method: "http", Target: up.URL,
		IntervalSeconds: 30, TimeoutSeconds: 2, Enabled: 1,
	})
	require.NoError(t, err2)

	svc.runChecks(ctx)

	// The status cache must show the any-success verdict.
	require.Equal(t, "online", svc.cachedStatus(devID))

	// The probe enqueued its result row AND the verdict enqueued a liveness
	// sample (the store's own loop commits them on a 5s cadence — asserting
	// queue occupancy here keeps the test inside the pre-flush window; the
	// commit path itself is covered by TestHeartbeatStore_*).
	require.Eventually(t, func() bool {
		return len(hbStore.ch) > 0 && len(hbStore.liveCh) > 0
	}, 3*time.Second, 50*time.Millisecond, "probe must enqueue a result + liveness sample")
}

// TestHeartbeatService_RunChecks_OfflineAfterThreshold pins the failure
// aggregation: an unreachable target keeps the device online until the
// offline threshold of failing ticks is crossed, then flips it offline.
func TestHeartbeatService_RunChecks_OfflineAfterThreshold(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	svc.cfg.OfflineThreshold = 2
	svc.cfg.TickIntervalSeconds = 1
	ctx := context.Background()

	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing listens → immediate refusal

	devID := insertTestDevice(t, queries, ctx, "dead-host", "127.0.0.1")
	_, err := queries.CreateHeartbeatConfig(ctx, sqldb.CreateHeartbeatConfigParams{
		DeviceID: devID, Method: "http", Target: deadURL,
		IntervalSeconds: 1, TimeoutSeconds: 1, Enabled: 1,
	})
	require.NoError(t, err)
	// Steady state: the device was online before it died (initStatusCache
	// would have loaded this on a running system; the fixture seeds the row
	// after init, so set it explicitly).
	svc.statusCacheMu.Lock()
	svc.statusCache[devID] = "online"
	svc.statusCacheMu.Unlock()

	svc.runChecks(ctx)
	require.Equal(t, "online", svc.cachedStatus(devID), "first failure stays online (1 < threshold 2)")
	time.Sleep(1100 * time.Millisecond) // let the 1s config interval elapse so the next tick is due
	svc.runChecks(ctx)
	require.Equal(t, "offline", svc.cachedStatus(devID), "second consecutive failure crosses the threshold")

	// ResetFailures clears the counter (the scan-revival path).
	svc.ResetFailures(devID)
	svc.failCountsMu.Lock()
	require.Equal(t, 0, svc.failCounts[devID])
	svc.failCountsMu.Unlock()
}

// TestHeartbeatService_CreateDefaultConfig pins the default ICMP seeding used
// by the device bridge: method icmp, 30s interval, target = device IP.
func TestHeartbeatService_CreateDefaultConfig(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()
	devID := insertTestDevice(t, queries, ctx, "default-cfg-host", "10.7.0.1")

	require.NoError(t, svc.CreateDefaultConfig(ctx, devID, "10.7.0.1"))

	cfgs, err := queries.ListHeartbeatConfigsByDevice(ctx, devID)
	require.NoError(t, err)
	require.Len(t, cfgs, 1)
	require.Equal(t, "icmp", cfgs[0].Method)
	require.Equal(t, "10.7.0.1", cfgs[0].Target)
	require.Equal(t, int64(30), cfgs[0].IntervalSeconds)
	require.Equal(t, int64(1), cfgs[0].Enabled)
}

// TestHeartbeatService_IsDue_CadenceRules covers the interval-fallback branch
// and the lastProbe bookkeeping that keeps ticks from double-scheduling.
func TestHeartbeatService_IsDue_CadenceRules(t *testing.T) {
	svc, _, _ := setupHeartbeatTest(t)
	svc.cfg.TickIntervalSeconds = 0 // forces the 30s fallback inside isDue

	cfg := sqldb.HeartbeatConfig{ID: 77, IntervalSeconds: 0}
	require.True(t, svc.isDue(context.Background(), cfg), "never-probed config is due")

	svc.lastProbeMu.Lock()
	svc.lastProbe[77] = time.Now()
	svc.lastProbeMu.Unlock()
	require.False(t, svc.isDue(context.Background(), cfg), "just-probed 0-interval config waits one tick")

	svc.lastProbeMu.Lock()
	svc.lastProbe[77] = time.Now().Add(-time.Minute)
	svc.lastProbeMu.Unlock()
	require.True(t, svc.isDue(context.Background(), cfg), "30s elapsed → due again")
}

// --- heartbeat store: deletion + offline-duration surfaces ---

func TestHeartbeatStore_DeleteAndLivenessSurfaces(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()
	devID := insertTestDevice(t, queries, ctx, "store-host", "10.7.0.2")

	// Seed a result row + a liveness sample through the store's batch paths.
	svc.store.Enqueue(resultRow{DeviceID: devID, ConfigID: 1, Status: "success", LatencyMs: 12.5, CheckedAt: time.Now()})
	svc.store.EnqueueLiveness(livenessRow{DeviceID: devID, Status: "online", Source: "test", CheckedAt: time.Now()})
	require.NoError(t, svc.store.commitBatch(ctx, []resultRow{{DeviceID: devID, ConfigID: 1, Status: "success", LatencyMs: 12.5, CheckedAt: time.Now()}}))
	require.NoError(t, svc.store.commitLivenessBatch(ctx, []livenessRow{{DeviceID: devID, Status: "online", Source: "test", CheckedAt: time.Now()}}))

	require.NoError(t, svc.store.DeleteByDevice(ctx, devID))
	require.NoError(t, svc.store.DeleteAllLiveness(ctx))

	dur, found, err := svc.store.OfflineDuration(ctx, devID)
	require.NoError(t, err)
	require.False(t, found, "no offline sample remains after the wipe")
	require.Equal(t, time.Duration(0), dur)
}

// --- device repo: list/count surfaces over the full schema ---

func TestDeviceRepo_CountingSurfaces(t *testing.T) {
	repo, conn, queries, ctx := setupDeviceRepoGap(t)

	// Three devices across two networks with distinct statuses/types.
	net1 := seedGapNetwork(t, ctx, queries, "lan-a")
	net2 := seedGapNetwork(t, ctx, queries, "lan-b")
	seedRepoDevice(t, ctx, conn, "d1", "10.8.0.1", "online", "camera", net1)
	seedRepoDevice(t, ctx, conn, "d2", "10.8.0.2", "offline", "camera", net1)
	seedRepoDevice(t, ctx, conn, "d3", "10.8.1.1", "online", "switch", net2)

	statusRows, err := repo.CountByStatusForNetwork(ctx, &net1)
	require.NoError(t, err)
	statusMap := map[string]int64{}
	for _, r := range statusRows {
		statusMap[r.Status] = r.Count
	}
	require.Equal(t, int64(1), statusMap["online"])
	require.Equal(t, int64(1), statusMap["offline"])

	typeRows, err := repo.CountByTypeForNetwork(ctx, &net1)
	require.NoError(t, err)
	require.Len(t, typeRows, 1)
	require.Equal(t, "camera", typeRows[0].Type)
	require.Equal(t, int64(2), typeRows[0].Count)

	list, err := repo.List(ctx, domain.DeviceFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, list, 3)

	n, err := repo.Count(ctx, domain.DeviceFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(3), n)

	filtered, err := repo.ListFiltered(ctx, domain.DeviceFilter{Search: "d1", Limit: 10})
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	filteredCount, err := repo.CountFiltered(ctx, domain.DeviceFilter{Search: "d1"})
	require.NoError(t, err)
	require.Equal(t, int64(1), filteredCount)
}

// --- TOTP service: backup-code validation + disable branches ---

func TestTOTPService_ValidateBackupCode(t *testing.T) {
	svc, dbConn, queries := setupTOTPGap(t)
	ctx := context.Background()
	_ = dbConn

	var userID int64
	res, err := dbConn.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('bc', 'bc@t', 'x', 'viewer')`)
	require.NoError(t, err)
	userID, _ = res.LastInsertId()

	resp, err := svc.Setup(ctx, userID, "bc")
	require.NoError(t, err)
	require.NotEmpty(t, resp.BackupCodes)

	var codes []string
	require.NoError(t, json.Unmarshal(resp.BackupCodes, &codes))
	require.NotEmpty(t, codes)

	// Matching code → true; wrong code → false; unknown user → TOTP-not-found.
	ok, err := svc.ValidateBackupCode(ctx, userID, codes[0])
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = svc.ValidateBackupCode(ctx, userID, "00000000")
	require.NoError(t, err)
	require.False(t, ok)
	_, err = svc.ValidateBackupCode(ctx, 9999, "00000000")
	require.ErrorIs(t, err, ErrTOTPNotFound)
	_ = queries
}

// --- dashboard upstream error ---

func TestUpstreamError_Error(t *testing.T) {
	e := &UpstreamError{Err: errors.New("connection refused to prometheus:9090")}
	require.Contains(t, e.Error(), "data source unreachable")
	require.Contains(t, e.Error(), "prometheus:9090")
}

// --- shared helpers ---

func setupDeviceRepoGap(t *testing.T) (*DeviceRepository, *sql.DB, *sqldb.Queries, context.Context) {
	t.Helper()
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	queries := sqldb.New(dbConn)
	return NewDeviceRepository(dbConn), dbConn, queries, context.Background()
}

func seedGapNetwork(t *testing.T, ctx context.Context, q *sqldb.Queries, name string) int64 {
	t.Helper()
	net, err := q.CreateNetwork(ctx, sqldb.CreateNetworkParams{Name: name})
	require.NoError(t, err)
	return net.ID
}

func seedRepoDevice(t *testing.T, ctx context.Context, conn *sql.DB, name, ip, status, typ string, networkID int64) {
	t.Helper()
	_, err := conn.ExecContext(ctx, `INSERT INTO devices (device_uuid, name, ip_address, status, type, network_id)
		VALUES (?, ?, ?, ?, ?, ?)`, "uuid-r6-"+name, name, ip, status, typ, networkID)
	require.NoError(t, err)
}

func setupTOTPGap(t *testing.T) (*TOTPService, *sql.DB, *sqldb.Queries) {
	t.Helper()
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	return NewTOTPService(dbConn, nil), dbConn, sqldb.New(dbConn)
}
