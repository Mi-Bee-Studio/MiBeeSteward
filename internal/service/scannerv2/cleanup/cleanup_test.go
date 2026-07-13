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
	old := now.AddDate(0, 0, -100) // 100 days ago — beyond the 90d default
	// Seed: a device (needed for the FK) + two neighbor edges, one old + one fresh.
	require.NoError(t, createSwitch(t, queries, "switch-1"))
	seedNeighbor(t, conn, 1, "aa:bb:cc:dd:ee:01", "LLDP", &old)
	seedNeighbor(t, conn, 1, "aa:bb:cc:dd:ee:02", "Bridge-MIB", &now)

	// Run with a 90-day window. The old edge should be removed; the fresh one kept.
	svc := New(queries, nil, config.RetentionConfig{
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

	svc := New(queries, nil, config.RetentionConfig{
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
