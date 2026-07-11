package service

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"

	_ "modernc.org/sqlite"
)

// setupHeartbeatTest creates an in-memory SQLite DB with all required tables
// and returns a HeartbeatService and raw queries ready for testing.
func setupHeartbeatTest(t *testing.T) (*HeartbeatService, *sql.DB, *db.Queries) {
	t.Helper()

	dbConn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })

	// Create devices table (matches migration schema)
	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS networks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			cidr TEXT, site TEXT, agent_id TEXT,
			metadata TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other' CHECK(type IN ('pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas')),
			brand TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			purpose TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('online', 'offline', 'unknown')),
			ip_address TEXT NOT NULL DEFAULT '',
			mac_address TEXT NOT NULL DEFAULT '',
			serial_number TEXT NOT NULL DEFAULT '',
			purchase_date TEXT NOT NULL DEFAULT '',
			warranty_expiry TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '{}',
			scan_source TEXT NOT NULL DEFAULT 'manual',
			prometheus_labels TEXT NOT NULL DEFAULT '{}',
			last_scanned_at TIMESTAMP,
			last_scan_task_id INTEGER,
			open_ports TEXT NOT NULL DEFAULT '[]',
			detected_services TEXT NOT NULL DEFAULT '[]',
			prometheus_url TEXT NOT NULL DEFAULT '',
			node_exporter_url TEXT NOT NULL DEFAULT '',
			last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
			scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
			user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
			scan_vendor   TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.vendor')) STORED,
			scan_mac      TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.mac')) STORED,
			scan_os       TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.os')) STORED,
			scan_hostname TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.hostname')) STORED,
			network_id INTEGER,
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// Create heartbeat_configs table (matches migration schema)
	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS heartbeat_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			method TEXT NOT NULL CHECK(method IN ('icmp', 'http', 'tcp', 'snmp')),
			target TEXT NOT NULL,
			interval_seconds INTEGER NOT NULL DEFAULT 30,
			timeout_seconds INTEGER NOT NULL DEFAULT 5,
			snmp_community TEXT NOT NULL DEFAULT 'public',
			snmp_oid TEXT NOT NULL DEFAULT '1.3.6.1.2.1.1.3.0',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// Create heartbeat_results table (matches migration schema)
	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS heartbeat_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			config_id INTEGER NOT NULL REFERENCES heartbeat_configs(id) ON DELETE CASCADE,
			status TEXT NOT NULL CHECK(status IN ('success', 'fail', 'timeout')),
			latency_ms REAL NOT NULL DEFAULT 0,
			error_message TEXT NOT NULL DEFAULT '',
			checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// Create indexes
	_, err = dbConn.Exec(`
		CREATE INDEX IF NOT EXISTS idx_heartbeat_results_device ON heartbeat_results(device_id, checked_at);
		CREATE INDEX IF NOT EXISTS idx_heartbeat_results_checked_at ON heartbeat_results(checked_at);
	`)
	require.NoError(t, err)

	cfg := &config.Config{
		Heartbeat: config.HeartbeatConfig{
			DefaultInterval: 60,
			Timeout:         5,
			RetentionDays:   30,
		},
	}

	// Heartbeat results now live in a dedicated store (separate DB). Use a
	// temp file so the test exercises the real batched-write path.
	hbStore, err := OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb_test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { hbStore.Close() })
	hbStore.Start(context.Background())

	svc := NewHeartbeatService(dbConn, hbStore, cfg)
	svc.initStatusCache(context.Background())
	queries := db.New(dbConn)

	return svc, dbConn, queries
}

// insertTestDevice inserts a device via raw queries and returns its ID.
//
//nolint:revive // test helper: t *testing.T is conventionally first for helpers
func insertTestDevice(t *testing.T, q *db.Queries, ctx context.Context, name, ipAddr string) int64 {
	t.Helper()
	device, err := q.CreateDevice(ctx, db.CreateDeviceParams{
		Name:           name,
		Type:           "other",
		Status:         "unknown",
		IpAddress:      ipAddr,
		Tags:           "{}",
		UserAttributes: "{}",
	})
	require.NoError(t, err)
	return device.ID
}

// insertTestConfig inserts a heartbeat config via raw queries and returns it.
//
//nolint:revive // test helper: t *testing.T is conventionally first for helpers
func insertTestConfig(t *testing.T, q *db.Queries, ctx context.Context, deviceID int64, method, target string, enabled int64) db.HeartbeatConfig {
	t.Helper()
	cfg, err := q.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
		DeviceID:        deviceID,
		Method:          method,
		Target:          target,
		IntervalSeconds: 60,
		TimeoutSeconds:  5,
		SnmpCommunity:   "public",
		SnmpOid:         "1.3.6.1.2.1.1.3.0",
		Enabled:         enabled,
	})
	require.NoError(t, err)
	return cfg
}

// ---------- Test Cases ----------

// 1. Create ICMP heartbeat config for a device
func TestHeartbeat_CreateConfig_ICMP(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-icmp", "192.168.1.1")

	q := svc.GetQueries()
	cfg, err := q.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
		DeviceID:        deviceID,
		Method:          "icmp",
		Target:          "192.168.1.1",
		IntervalSeconds: 30,
		TimeoutSeconds:  5,
		SnmpCommunity:   "public",
		SnmpOid:         "1.3.6.1.2.1.1.3.0",
		Enabled:         1,
	})
	require.NoError(t, err)
	require.NotZero(t, cfg.ID)
	require.Equal(t, deviceID, cfg.DeviceID)
	require.Equal(t, "icmp", cfg.Method)
	require.Equal(t, "192.168.1.1", cfg.Target)
	require.Equal(t, int64(30), cfg.IntervalSeconds)
	require.Equal(t, int64(1), cfg.Enabled)

	// Verify retrieval
	got, err := q.GetHeartbeatConfig(ctx, cfg.ID)
	require.NoError(t, err)
	require.Equal(t, cfg.ID, got.ID)
	require.Equal(t, "icmp", got.Method)
}

// 2. Create HTTP heartbeat config
func TestHeartbeat_CreateConfig_HTTP(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-http", "10.0.0.1")

	q := svc.GetQueries()
	cfg, err := q.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
		DeviceID:        deviceID,
		Method:          "http",
		Target:          "http://10.0.0.1/health",
		IntervalSeconds: 60,
		TimeoutSeconds:  10,
		SnmpCommunity:   "public",
		SnmpOid:         "1.3.6.1.2.1.1.3.0",
		Enabled:         1,
	})
	require.NoError(t, err)
	require.NotZero(t, cfg.ID)
	require.Equal(t, "http", cfg.Method)
	require.Equal(t, "http://10.0.0.1/health", cfg.Target)
	require.Equal(t, int64(60), cfg.IntervalSeconds)
	require.Equal(t, int64(10), cfg.TimeoutSeconds)
}

// 3. Create with invalid probe method → CHECK constraint error
func TestHeartbeat_CreateConfig_InvalidMethod(t *testing.T) {
	_, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-invalid", "10.0.0.2")

	_, err := queries.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
		DeviceID:        deviceID,
		Method:          "invalid",
		Target:          "10.0.0.2",
		IntervalSeconds: 30,
		TimeoutSeconds:  5,
		SnmpCommunity:   "public",
		SnmpOid:         "1.3.6.1.2.1.1.3.0",
		Enabled:         1,
	})
	require.Error(t, err, "expected CHECK constraint error for invalid method")
}

// 4. Update config interval and target
func TestHeartbeat_UpdateConfig(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-update", "192.168.2.1")
	original := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.2.1", 1)

	q := svc.GetQueries()
	updated, err := q.UpdateHeartbeatConfig(ctx, db.UpdateHeartbeatConfigParams{
		ID:              original.ID,
		Method:          "tcp",
		Target:          "192.168.2.1:8080",
		IntervalSeconds: 120,
		TimeoutSeconds:  10,
		SnmpCommunity:   "public",
		SnmpOid:         "1.3.6.1.2.1.1.3.0",
		Enabled:         1,
	})
	require.NoError(t, err)
	require.Equal(t, original.ID, updated.ID)
	require.Equal(t, "tcp", updated.Method)
	require.Equal(t, "192.168.2.1:8080", updated.Target)
	require.Equal(t, int64(120), updated.IntervalSeconds)
	require.Equal(t, int64(10), updated.TimeoutSeconds)
}

// 5. Create then delete config
func TestHeartbeat_DeleteConfig(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-delete", "192.168.3.1")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.3.1", 1)

	q := svc.GetQueries()
	rowsAffected, err := q.DeleteHeartbeatConfig(ctx, cfg.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), rowsAffected)

	// Verify it's gone
	_, err = q.GetHeartbeatConfig(ctx, cfg.ID)
	require.Error(t, err, "expected error getting deleted config")
}

// 6. Create multiple configs for device, list them
func TestHeartbeat_ListConfigsByDevice(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-list", "192.168.4.1")
	otherDeviceID := insertTestDevice(t, queries, ctx, "other-device", "192.168.4.2")

	insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.4.1", 1)
	insertTestConfig(t, queries, ctx, deviceID, "http", "http://192.168.4.1/health", 1)
	insertTestConfig(t, queries, ctx, deviceID, "tcp", "192.168.4.1:443", 1)
	// Different device — should not appear
	insertTestConfig(t, queries, ctx, otherDeviceID, "icmp", "192.168.4.2", 1)

	q := svc.GetQueries()
	configs, err := q.ListHeartbeatConfigsByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, configs, 3)

	for _, c := range configs {
		require.Equal(t, deviceID, c.DeviceID)
	}
}

// 7. Create a heartbeat result (success)
func TestHeartbeat_CreateResult(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-result", "192.168.5.1")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.5.1", 1)

	q := svc.GetQueries()
	now := time.Now()
	result, err := q.CreateResult(ctx, db.CreateResultParams{
		DeviceID:     deviceID,
		ConfigID:     cfg.ID,
		Status:       "success",
		LatencyMs:    12.5,
		ErrorMessage: "",
		CheckedAt:    now,
	})
	require.NoError(t, err)
	require.NotZero(t, result.ID)
	require.Equal(t, deviceID, result.DeviceID)
	require.Equal(t, cfg.ID, result.ConfigID)
	require.Equal(t, "success", result.Status)
	require.InDelta(t, 12.5, result.LatencyMs, 0.01)
	require.Empty(t, result.ErrorMessage)
}

// 8. Create a heartbeat result (failure)
func TestHeartbeat_CreateResult_Failure(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-fail", "192.168.5.2")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.5.2", 1)

	q := svc.GetQueries()
	result, err := q.CreateResult(ctx, db.CreateResultParams{
		DeviceID:     deviceID,
		ConfigID:     cfg.ID,
		Status:       "fail",
		LatencyMs:    0,
		ErrorMessage: "destination host unreachable",
		CheckedAt:    time.Now(),
	})
	require.NoError(t, err)
	require.Equal(t, "fail", result.Status)
	require.Equal(t, "destination host unreachable", result.ErrorMessage)
	require.InDelta(t, 0, result.LatencyMs, 0.01)
}

// 9. Insert old results, cleanup, verify removed
func TestHeartbeat_CleanupOldResults(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-cleanup", "192.168.7.1")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.7.1", 1)

	q := svc.GetQueries()

	// Insert an old result (60 days ago)
	_, err := q.CreateResult(ctx, db.CreateResultParams{
		DeviceID:     deviceID,
		ConfigID:     cfg.ID,
		Status:       "success",
		LatencyMs:    5.0,
		ErrorMessage: "",
		CheckedAt:    time.Now().AddDate(0, 0, -60),
	})
	require.NoError(t, err)

	// Insert a recent result (1 hour ago)
	recentResult, err := q.CreateResult(ctx, db.CreateResultParams{
		DeviceID:     deviceID,
		ConfigID:     cfg.ID,
		Status:       "success",
		LatencyMs:    3.0,
		ErrorMessage: "",
		CheckedAt:    time.Now().Add(-1 * time.Hour),
	})
	require.NoError(t, err)

	// Run cleanup with 30-day retention
	cutoff := time.Now().AddDate(0, 0, -30)
	deleted, err := q.DeleteOlderThan(ctx, cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted, "expected 1 old result to be deleted")

	// Verify the recent result still exists
	got, err := q.GetLatestCheckedAt(ctx, cfg.ID)
	require.NoError(t, err)
	require.WithinDuration(t, recentResult.CheckedAt, got, 2*time.Second)

	// Only 1 result remains
	results, err := q.ListHeartbeatResultsByDevice(ctx, db.ListHeartbeatResultsByDeviceParams{
		DeviceID: deviceID,
		Column2:  "",
		Column4:  "",
		Limit:    100,
		Offset:   0,
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
}

// 10. Create disabled config, verify not in ListEnabledConfigs
func TestHeartbeat_ConfigDisabled(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-disabled", "192.168.8.1")

	// Disabled config
	insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.8.1", 0)
	// Enabled config
	insertTestConfig(t, queries, ctx, deviceID, "http", "http://192.168.8.1/health", 1)

	q := svc.GetQueries()

	enabledConfigs, err := q.ListEnabledConfigs(ctx)
	require.NoError(t, err)
	require.Len(t, enabledConfigs, 1)
	require.Equal(t, "http", enabledConfigs[0].Method)
	require.Equal(t, int64(1), enabledConfigs[0].Enabled)

	// Total configs for device = 2
	allConfigs, err := q.ListHeartbeatConfigsByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, allConfigs, 2)
}

// 11. GetLatestCheckedAt returns error when no results exist
func TestHeartbeat_GetLatestCheckedAt_NoResults(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-nolatest", "192.168.9.1")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.9.1", 1)

	q := svc.GetQueries()
	_, err := q.GetLatestCheckedAt(ctx, cfg.ID)
	require.Error(t, err, "expected error when no results exist")
}

// 12. updateDeviceStatus: success path → device goes online
func TestHeartbeat_UpdateDeviceStatus_Success(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-status", "192.168.10.1")

	// Set device to offline first
	_, err := queries.UpdateDevice(ctx, db.UpdateDeviceParams{
		ID:        deviceID,
		Name:      "test-device-status",
		Type:      "other",
		Status:    "offline",
		IpAddress: "192.168.10.1",
		Tags:      "{}",
	})
	require.NoError(t, err)
	svc.initStatusCache(ctx)

	// Successful probe → should set online
	svc.applyDeviceVerdict(deviceID, true)

	require.Equal(t, "online", svc.cachedStatus(deviceID))
}

// 13. updateDeviceStatus: failure threshold (3 consecutive) → device goes offline
func TestHeartbeat_UpdateDeviceStatus_FailureThreshold(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-threshold", "192.168.10.2")

	// Set device to online first
	_, err := queries.UpdateDevice(ctx, db.UpdateDeviceParams{
		ID:        deviceID,
		Name:      "test-device-threshold",
		Type:      "other",
		Status:    "online",
		IpAddress: "192.168.10.2",
		Tags:      "{}",
	})
	require.NoError(t, err)
	svc.initStatusCache(ctx)

	// Failures 1-4 → still online (threshold is 5)
	svc.applyDeviceVerdict(deviceID, false)
	require.Equal(t, "online", svc.cachedStatus(deviceID), "still online after 1 failure")

	svc.applyDeviceVerdict(deviceID, false)
	svc.applyDeviceVerdict(deviceID, false)
	svc.applyDeviceVerdict(deviceID, false)
	require.Equal(t, "online", svc.cachedStatus(deviceID), "still online after 4 failures")

	// Failure 5 → threshold reached → offline
	svc.applyDeviceVerdict(deviceID, false)
	require.Equal(t, "offline", svc.cachedStatus(deviceID), "offline after 5 consecutive failures")
}

// 14. GetProber returns correct prober types
func TestHeartbeat_GetProber(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{"icmp", "icmp"},
		{"http", "http"},
		{"tcp", "tcp"},
		{"snmp", "snmp"},
		{"unknown defaults to icmp", "unknown"},
		{"empty defaults to icmp", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := GetProber(tt.method, "public", "1.3.6.1.2.1.1.3.0")
			require.NotNil(t, p)
		})
	}
}

// 15. Success resets failure counter and failure after success does not double-count
func TestHeartbeat_UpdateDeviceStatus_SuccessResetsFailCounter(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-device-reset", "192.168.11.1")

	// Set device online
	_, err := queries.UpdateDevice(ctx, db.UpdateDeviceParams{
		ID:        deviceID,
		Name:      "test-device-reset",
		Type:      "other",
		Status:    "online",
		IpAddress: "192.168.11.1",
		Tags:      "{}",
	})
	require.NoError(t, err)
	svc.initStatusCache(ctx)

	// 2 failures
	svc.applyDeviceVerdict(deviceID, false)
	svc.applyDeviceVerdict(deviceID, false)

	// 1 success → resets counter
	svc.applyDeviceVerdict(deviceID, true)

	// 4 more failures → counter is now 4, should NOT trigger offline (threshold 5)
	svc.applyDeviceVerdict(deviceID, false)
	svc.applyDeviceVerdict(deviceID, false)
	svc.applyDeviceVerdict(deviceID, false)
	svc.applyDeviceVerdict(deviceID, false)

	require.Equal(t, "online", svc.cachedStatus(deviceID), "device should remain online — failure counter was reset")

	// 5th failure → offline
	svc.applyDeviceVerdict(deviceID, false)
	require.Equal(t, "offline", svc.cachedStatus(deviceID), "offline after 5 consecutive failures post-reset")
}

// 16. GetHistory returns paginated results within time range
func TestHeartbeat_GetHistory(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-history", "192.168.20.1")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.20.1", 1)

	now := time.Now()
	// Insert results into the heartbeat store (separate DB).
	hq := svc.Store().Queries()
	for i := 0; i < 3; i++ {
		_, err := hq.CreateResult(ctx, db.CreateResultParams{
			DeviceID:     deviceID,
			ConfigID:     cfg.ID,
			Status:       "success",
			LatencyMs:    float64(i+1) * 10,
			ErrorMessage: "",
			CheckedAt:    now.Add(-time.Duration(i) * time.Hour),
		})
		require.NoError(t, err)
	}

	from := now.Add(-2 * time.Hour)
	to := now.Add(time.Hour)

	resp, err := svc.GetHistory(ctx, deviceID, from, to, 100, 0)
	require.NoError(t, err)
	require.Len(t, resp.Results, 3)
	require.Equal(t, 3, resp.Total)

	// Time range that excludes oldest
	narrowFrom := now.Add(-30 * time.Minute)
	resp, err = svc.GetHistory(ctx, deviceID, narrowFrom, to, 100, 0)
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	require.Equal(t, 1, resp.Total)
}

// 17. GetHistory pagination
func TestHeartbeat_GetHistoryPagination(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-history-page", "192.168.20.2")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.20.2", 1)

	now := time.Now()
	hq := svc.Store().Queries()
	for i := 0; i < 5; i++ {
		_, err := hq.CreateResult(ctx, db.CreateResultParams{
			DeviceID:     deviceID,
			ConfigID:     cfg.ID,
			Status:       "success",
			LatencyMs:    10.0,
			ErrorMessage: "",
			CheckedAt:    now.Add(-time.Duration(i) * time.Minute),
		})
		require.NoError(t, err)
	}

	from := now.Add(-24 * time.Hour)
	to := now.Add(time.Hour)

	resp, err := svc.GetHistory(ctx, deviceID, from, to, 2, 0)
	require.NoError(t, err)
	require.Len(t, resp.Results, 2)
	require.Equal(t, 5, resp.Total)

	resp, err = svc.GetHistory(ctx, deviceID, from, to, 2, 2)
	require.NoError(t, err)
	require.Len(t, resp.Results, 2)
	require.Equal(t, 5, resp.Total)
}

// 18. GetStats with mixed results
func TestHeartbeat_GetStats(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-stats", "192.168.30.1")
	cfg := insertTestConfig(t, queries, ctx, deviceID, "icmp", "192.168.30.1", 1)

	now := time.Now()
	statuses := []struct {
		status  string
		latency float64
	}{
		{"success", 10.0},
		{"success", 20.0},
		{"fail", 0},
		{"timeout", 0},
		{"success", 30.0},
	}

	// Insert results into the heartbeat STORE (separate DB), since that's where
	// GetStats reads from now.
	hq := svc.Store().Queries()
	for _, s := range statuses {
		_, err := hq.CreateResult(ctx, db.CreateResultParams{
			DeviceID:     deviceID,
			ConfigID:     cfg.ID,
			Status:       s.status,
			LatencyMs:    s.latency,
			ErrorMessage: "",
			CheckedAt:    now,
		})
		require.NoError(t, err)
	}

	from := now.Add(-24 * time.Hour)
	to := now.Add(time.Hour)

	stats, err := svc.GetStats(ctx, deviceID, from, to)
	require.NoError(t, err)
	require.InDelta(t, 12.0, stats.AvgLatencyMs, 0.01) // (10+20+0+0+30)/5 = 12
	require.Equal(t, int64(3), stats.SuccessCount)
	require.Equal(t, int64(1), stats.FailCount)
	require.Equal(t, int64(1), stats.TimeoutCount)
}

// 19. GetStats with no results returns zero values
func TestHeartbeat_GetStatsEmpty(t *testing.T) {
	svc, _, _ := setupHeartbeatTest(t)
	ctx := context.Background()

	now := time.Now()
	from := now.Add(-24 * time.Hour)
	to := now.Add(time.Hour)

	stats, err := svc.GetStats(ctx, 999, from, to)
	require.NoError(t, err)
	require.InDelta(t, 0.0, stats.AvgLatencyMs, 0.01)
	require.Equal(t, int64(0), stats.SuccessCount)
	require.Equal(t, int64(0), stats.FailCount)
	require.Equal(t, int64(0), stats.TimeoutCount)
}

// ---------- CreateConfigs Tests (TDD) ----------

// 1. Single ICMP config → creates 1 heartbeat_config record
func TestCreateConfigs_SingleICMP(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-create-configs-icmp", "192.168.50.1")

	configs := []scannerv2.HeartbeatSpec{
		{
			Method:          "icmp",
			Target:          "192.168.50.1",
			IntervalSeconds: 30,
			TimeoutSeconds:  5,
			SNMPCommunity:   "public",
			SNMPOID:         "1.3.6.1.2.1.1.3.0",
		},
	}
	err := svc.CreateConfigs(ctx, deviceID, configs)
	require.NoError(t, err)

	// Verify 1 record created
	rows, err := queries.ListHeartbeatConfigsByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "icmp", rows[0].Method)
	require.Equal(t, "192.168.50.1", rows[0].Target)
	require.Equal(t, int64(30), rows[0].IntervalSeconds)
	require.Equal(t, int64(1), rows[0].Enabled)
}

// 2. Multiple configs (ICMP + SNMP) → creates 2 records
func TestCreateConfigs_MultipleMethods(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-create-configs-multi", "192.168.51.1")

	configs := []scannerv2.HeartbeatSpec{
		{
			Method:          "icmp",
			Target:          "192.168.51.1",
			IntervalSeconds: 30,
			TimeoutSeconds:  5,
			SNMPCommunity:   "public",
			SNMPOID:         "1.3.6.1.2.1.1.3.0",
		},
		{
			Method:          "snmp",
			Target:          "192.168.51.1",
			IntervalSeconds: 60,
			TimeoutSeconds:  10,
			SNMPCommunity:   "private",
			SNMPOID:         "1.3.6.1.2.1.1.1.0",
		},
	}
	err := svc.CreateConfigs(ctx, deviceID, configs)
	require.NoError(t, err)

	// Verify 2 records created
	rows, err := queries.ListHeartbeatConfigsByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	methods := map[string]bool{}
	for _, r := range rows {
		methods[r.Method] = true
	}
	require.True(t, methods["icmp"], "expected ICMP config")
	require.True(t, methods["snmp"], "expected SNMP config")
}

// 3. Empty configs slice → returns nil (no-op)
func TestCreateConfigs_EmptySlice(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-create-configs-empty", "192.168.52.1")

	err := svc.CreateConfigs(ctx, deviceID, nil)
	require.NoError(t, err)

	err = svc.CreateConfigs(ctx, deviceID, []scannerv2.HeartbeatSpec{})
	require.NoError(t, err)

	// Verify no records created
	rows, err := queries.ListHeartbeatConfigsByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, rows, 0)
}

// 4. Invalid method → returns error
func TestCreateConfigs_InvalidMethod(t *testing.T) {
	svc, _, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	deviceID := insertTestDevice(t, queries, ctx, "test-create-configs-invalid", "192.168.53.1")

	configs := []scannerv2.HeartbeatSpec{
		{
			Method:          "ftp",
			Target:          "192.168.53.1",
			IntervalSeconds: 30,
			TimeoutSeconds:  5,
		},
	}
	err := svc.CreateConfigs(ctx, deviceID, configs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid heartbeat method")
	require.Contains(t, err.Error(), "ftp")

	// Verify no records created
	rows, err := queries.ListHeartbeatConfigsByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Len(t, rows, 0)
}

// TestHeartbeat_ListEnabledConfigs_ExcludesAgentNetwork confirms the center does
// NOT probe devices on agent-managed networks (networks.agent_id non-empty) —
// those devices' liveness comes from agent reports, not local ICMP/TCP probes.
// This is the fix for the cross-subnet false-offline bug.
func TestHeartbeat_ListEnabledConfigs_ExcludesAgentNetwork(t *testing.T) {
	svc, dbConn, queries := setupHeartbeatTest(t)
	ctx := context.Background()

	// Create a center network (agent_id empty) + an agent network (agent_id set).
	centerNet, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "center"})
	require.NoError(t, err)
	_, err = dbConn.ExecContext(ctx,
		`INSERT INTO networks (name, agent_id, metadata) VALUES ('agent-net', 'agent-62', '{}')`)
	require.NoError(t, err)
	var agentNetID int64
	dbConn.QueryRowContext(ctx, `SELECT id FROM networks WHERE name = 'agent-net'`).Scan(&agentNetID)

	// Center device: network_id = centerNet.ID (agent_id empty → probed).
	centerDev := insertTestDevice(t, queries, ctx, "center-device", "192.168.63.50")
	_, err = dbConn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, centerNet.ID, centerDev)
	require.NoError(t, err)
	insertTestConfig(t, queries, ctx, centerDev, "icmp", "192.168.63.50", 1)

	// Agent device: network_id = agentNetID (agent_id set → excluded from probing).
	agentDev := insertTestDevice(t, queries, ctx, "agent-device", "192.168.62.41")
	_, err = dbConn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, agentNetID, agentDev)
	require.NoError(t, err)
	insertTestConfig(t, queries, ctx, agentDev, "icmp", "192.168.62.41", 1)

	q := svc // same package: call the private method directly
	enabled, err := q.listLocalProbeConfigs(ctx)
	require.NoError(t, err)

	// Only the center device's config should appear.
	require.Len(t, enabled, 1, "agent-network config must be excluded")
	require.Equal(t, centerDev, enabled[0].DeviceID, "only center-network device probed")
}
