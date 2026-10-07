package cleanup

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// TestPruneDeviceNeighbors verifies the device_neighbors retention sweep:
// rows older than the cutoff are deleted in batches, rows within the window
// are kept, and a zero-days config never deletes anything (the safety guard).
func TestPruneDeviceNeighbors(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	now := time.Now().UTC()
	old := now.AddDate(0, 0, -100) // 100 days ago: beyond the 90d default
	// Seed: a device (needed for the FK) + two neighbor edges, one old + one fresh.
	require.NoError(t, createSwitch(t, queries, "switch-1"))
	seedNeighbor(t, conn, 1, "aa:bb:cc:dd:ee:01", "LLDP", &old)
	seedNeighbor(t, conn, 1, "aa:bb:cc:dd:ee:02", "Bridge-MIB", &now)

	// Run with a 90-day window. The old edge should be removed; the fresh one kept.
	svc := New(queries, nil, nil, nil, config.RetentionConfig{
		DeviceNeighborsDays: 90,
		BatchSize:           1000,
		SweepIntervalHours:  1,
	})
	svc.pruneDeviceNeighbors(ctx)

	count, err := queries.CountDeviceNeighbors(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), count, "old neighbor edge should be pruned, fresh one kept")
}

// TestPruneDeviceNeighbors_ZeroDaysGuard verifies the days<=0 safety guard:
// when DeviceNeighborsDays is 0 the sweep must NOT delete everything.
func TestPruneDeviceNeighbors_ZeroDaysGuard(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	old := time.Now().UTC().AddDate(0, 0, -365)
	require.NoError(t, createSwitch(t, queries, "switch-2"))
	seedNeighbor(t, conn, 2, "aa:bb:cc:dd:ee:03", "LLDP", &old)

	svc := New(queries, nil, nil, nil, config.RetentionConfig{
		DeviceNeighborsDays: 0, // not configured → guard: leave the table alone
		BatchSize:           1000,
		SweepIntervalHours:  1,
	})
	svc.pruneDeviceNeighbors(ctx)

	count, err := queries.CountDeviceNeighbors(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), count, "zero-days guard must not delete the row")
}

// seedNeighbor inserts a device_neighbors row directly (the sqlc upsert query
// takes a params struct; raw SQL here keeps the test focused on the sweep).
func seedNeighbor(t *testing.T, conn *sql.DB, deviceID int64, mac, protocol string, lastSeen *time.Time) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO device_neighbors (device_id, neighbor_mac, protocol, local_port, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		deviceID, mac, protocol, "1", lastSeen, lastSeen)
	require.NoError(t, err)
}

// createSwitch inserts a device with the minimum valid field set (the devices
// table has CHECK constraints on type/status and json_valid on tags/attrs).
func createSwitch(t *testing.T, queries *db.Queries, name string) error {
	t.Helper()
	_, err := queries.CreateDevice(context.Background(), db.CreateDeviceParams{
		Name:           name,
		Type:           "switch",
		Status:         "unknown",
		Tags:           "{}",
		UserAttributes: "{}",
	})
	return err
}

// TestPruneOrphanHeartbeatConfigs pins the 2026-10-08 field finding: the main
// DB does not enable SQLite's foreign_keys pragma, so ON DELETE CASCADE on
// heartbeat_configs never fires — deleting a device row (silent-device sweep,
// reconcile ghost cleanup, any future path) left its heartbeat configs behind,
// and the still-enabled configs kept probing a vanished IP forever (two
// orphans logged ~2300 ERRORs/day between them). The maintenance pass now
// reaps configs whose device_id no longer resolves.
func TestPruneOrphanHeartbeatConfigs(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	// createSwitch leaves device_uuid empty and the UNIQUE index rejects a
	// second empty uuid — insert the two rows with distinct uuids directly.
	_, err = conn.ExecContext(ctx, `INSERT INTO devices (name, type, status, device_uuid, tags, user_attributes)
		VALUES ('switch-1', 'switch', 'unknown', 'orphan-live', '{}', '{}'),
		       ('switch-2', 'switch', 'unknown', 'orphan-gone', '{}', '{}')`)
	require.NoError(t, err)
	// One config on a live device, one on a device we then delete WITHOUT any
	// cascade (mirroring what the silent-device sweep's DELETE actually does).
	seedHeartbeatConfig(t, conn, 1, "http", "http://192.0.2.10:80/")
	seedHeartbeatConfig(t, conn, 2, "http", "http://192.0.2.11:80/")
	_, err = conn.ExecContext(ctx, `DELETE FROM devices WHERE id = 2`)
	require.NoError(t, err)

	svc := New(queries, nil, nil, conn, config.RetentionConfig{BatchSize: 1000})
	svc.pruneOrphanHeartbeatConfigs(ctx)

	var n int
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM heartbeat_configs WHERE device_id NOT IN (SELECT id FROM devices)`).Scan(&n))
	require.Zero(t, n, "orphaned heartbeat configs must be reaped")

	var live int
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM heartbeat_configs WHERE device_id = 1`).Scan(&live))
	require.Equal(t, 1, live, "configs of live devices are untouched")
}

func seedHeartbeatConfig(t *testing.T, conn *sql.DB, deviceID int64, method, target string) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO heartbeat_configs (device_id, method, target, interval_seconds, timeout_seconds)
		 VALUES (?, ?, ?, 30, 5)`, deviceID, method, target)
	require.NoError(t, err)
}
