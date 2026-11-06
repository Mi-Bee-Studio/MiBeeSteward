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

// insertDevice inserts a devices row with full control over the fields the
// roamed-orphan prune keys on (scan_source, status, mac_address, offline_since).
// Returns the row id. Used instead of queries.CreateDevice because CreateDevice
// defaults scan_source='manual' and doesn't let us set offline_since, both
// critical to the prune logic under test.
func insertDevice(t *testing.T, conn *sql.DB, name, scanSource, status, mac, ip string, offlineSince *time.Time) int64 {
	t.Helper()
	var offline any
	if offlineSince != nil {
		offline = offlineSince.UTC().Format(time.RFC3339Nano)
	}
	res, err := conn.ExecContext(context.Background(), `
		INSERT INTO devices (device_uuid, name, type, status, scan_source, mac_address, ip_address, offline_since, tags, scan_attributes, user_attributes)
		VALUES (?, ?, 'other', ?, ?, ?, ?, ?, '{}', '{}', '{}')`,
		name+"-uuid", name, status, scanSource, mac, ip, offline)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// utcPtr returns a pointer to the UTC-normalized time (helper for the
// offlineSince *time.Time params above).
func utcPtr(t time.Time) *time.Time {
	u := t.UTC()
	return &u
}

// The silent-device prune tests (offline 7d/24h → physical DELETE) moved to
// internal/service/archive with the new semantics (#663): those devices are
// now ARCHIVED, not deleted. This file keeps the one remaining device-row
// delete: the roamed-orphan duplicate reap.

// TestPruneRoamedOrphans_OrphanDeleted verifies the cross-network migration
// cleanup: a device whose MAC exists ONLINE in another network AND whose
// offline_since is older than the roamed-orphan window is deleted (it's a
// stale old-network leftover, the live copy is elsewhere).
func TestPruneRoamedOrphans_OrphanDeleted(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	// Two networks so the same MAC can legitimately exist in both.
	net1, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "net-1"})
	require.NoError(t, err)
	net2, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "net-2"})
	require.NoError(t, err)

	// The orphan: offline 20min (> 10min roamed window) in net-1.
	orphanID := insertDevice(t, conn, "orphan", "scanner_v2", "offline", "aa:bb:cc:dd:ee:77", "192.0.2.77",
		utcPtr(time.Now().Add(-20*time.Minute)))
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net1.ID, orphanID)
	require.NoError(t, err)
	// The live copy: online in net-2, same MAC.
	liveID := insertDevice(t, conn, "live", "scanner_v2", "online", "aa:bb:cc:dd:ee:77", "198.51.100.77", nil)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net2.ID, liveID)
	require.NoError(t, err)

	svc := New(queries, nil, nil, conn, config.RetentionConfig{BatchSize: 1000})
	svc.pruneRoamedOrphans(ctx)

	var orphanGone int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE id = ?`, orphanID).Scan(&orphanGone))
	require.Equal(t, int64(0), orphanGone, "roamed orphan (MAC online elsewhere, offline > window) must be deleted")
	var liveKept int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE id = ?`, liveID).Scan(&liveKept))
	require.Equal(t, int64(1), liveKept, "the live online copy must be kept")
}

// TestPruneRoamedOrphans_KeepsRecent verifies the roamed-orphan prune does NOT
// fire too early: a device whose MAC is online elsewhere but whose
// offline_since is RECENT (< the roamed window) is kept, so an in-progress
// scan/roam can't race the prune.
func TestPruneRoamedOrphans_KeepsRecent(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	net1, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "net-1"})
	require.NoError(t, err)
	net2, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "net-2"})
	require.NoError(t, err)

	// Offline only 2min (< 10min roamed window), kept even though MAC is online elsewhere.
	recentID := insertDevice(t, conn, "recent-orphan", "scanner_v2", "offline", "aa:bb:cc:dd:ee:88", "192.0.2.88",
		utcPtr(time.Now().Add(-2*time.Minute)))
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net1.ID, recentID)
	require.NoError(t, err)
	liveID := insertDevice(t, conn, "live2", "scanner_v2", "online", "aa:bb:cc:dd:ee:88", "198.51.100.88", nil)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net2.ID, liveID)
	require.NoError(t, err)

	svc := New(queries, nil, nil, conn, config.RetentionConfig{BatchSize: 1000})
	svc.pruneRoamedOrphans(ctx)

	var kept int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE id = ?`, recentID).Scan(&kept))
	require.Equal(t, int64(1), kept, "recent-roam orphan (< window) must be kept")
}

// TestPruneRoamedOrphans_LogsDeviceRemoved verifies each deleted orphan gets a
// device_removed change_log row (with before snapshot + reason) BEFORE the
// delete, so the audit trail survives the CASCADE.
func TestPruneRoamedOrphans_LogsDeviceRemoved(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	// Orphan + live copy, same MAC: only the orphan is deleted.
	orphanID := insertDevice(t, conn, "audited-orphan", "scanner_v2", "offline", "aa:bb:cc:dd:ee:33", "192.0.2.33",
		utcPtr(time.Now().Add(-20*time.Minute)))
	liveID := insertDevice(t, conn, "audited-live", "scanner_v2", "online", "aa:bb:cc:dd:ee:33", "198.51.100.33", nil)
	require.NotZero(t, liveID)

	svc := New(queries, nil, nil, conn, config.RetentionConfig{BatchSize: 1000})
	svc.pruneRoamedOrphans(ctx)

	var n int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM change_log WHERE change_type = 'device_removed'`).Scan(&n))
	require.Equal(t, int64(1), n, "deleted orphan must get a device_removed change_log row")
	var reason string
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT agent_id FROM change_log WHERE change_type = 'device_removed' LIMIT 1`).Scan(&reason))
	require.Equal(t, "roamed_orphan", reason, "change_log agent_id carries the prune reason")
	require.NotZero(t, orphanID)
}

// TestPruneRoamedOrphans_SilentDeviceStays verifies the #663 semantic split:
// a plain offline device (MAC not online anywhere) is NOT deleted by the
// sweeper anymore — the asset-archive engine owns it now.
func TestPruneRoamedOrphans_SilentDeviceStays(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	id := insertDevice(t, conn, "silent-keeper", "scanner_v2", "offline", "aa:bb:cc:dd:ee:99", "192.0.2.99",
		utcPtr(time.Now().AddDate(0, 0, -30))) // offline 30d, no online duplicate

	svc := New(queries, nil, nil, conn, config.RetentionConfig{BatchSize: 1000})
	svc.pruneRoamedOrphans(ctx)

	var kept int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE id = ?`, id).Scan(&kept))
	require.Equal(t, int64(1), kept, "plain offline device must stay (archive engine owns it, #663)")
}
