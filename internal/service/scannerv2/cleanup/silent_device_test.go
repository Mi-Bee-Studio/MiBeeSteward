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
// silent-device prune keys on (scan_source, status, mac_address, offline_since).
// Returns the row id. Used instead of queries.CreateDevice because CreateDevice
// defaults scan_source='manual' and doesn't let us set offline_since — both
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

// countDevicesWithStatus counts devices matching the given status (helper for
// prune assertions).
func countDevicesWithStatus(t *testing.T, conn *sql.DB, status string) int64 {
	t.Helper()
	var c int64
	require.NoError(t, conn.QueryRowContext(context.Background(),
		`SELECT count(*) FROM devices WHERE status = ?`, status).Scan(&c))
	return c
}

// TestPruneSilentDevices_MAC_7d verifies a scanner-discovered device WITH a MAC
// is pruned only after the 7-day silent window (SilentDeviceDaysMAC).
func TestPruneSilentDevices_MAC_7d(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	// Device offline for 8 days (> 7d default) with a MAC → should be pruned.
	insertDevice(t, conn, "old-mac", "scanner_v2", "offline", "aa:bb:cc:dd:ee:01", "10.0.0.1",
		utcPtr(time.Now().AddDate(0, 0, -8)))
	// Device offline for 5 days (< 7d) with a MAC → should be KEPT.
	insertDevice(t, conn, "recent-mac", "scanner_v2", "offline", "aa:bb:cc:dd:ee:02", "10.0.0.2",
		utcPtr(time.Now().AddDate(0, 0, -5)))

	svc := New(queries, nil, nil, conn, config.RetentionConfig{
		SilentDeviceDaysMAC:    7,
		SilentDeviceHoursNoMAC: 24,
		BatchSize:              1000,
	})
	svc.pruneSilentDevices(ctx)

	var remaining int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE name = 'old-mac'`).Scan(&remaining))
	require.Equal(t, int64(0), remaining, "8-day-silent MAC device must be pruned")
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE name = 'recent-mac'`).Scan(&remaining))
	require.Equal(t, int64(1), remaining, "5-day-silent MAC device must be kept (< 7d window)")
}

// TestPruneSilentDevices_NoMAC_24h verifies a scanner-discovered device WITHOUT
// a MAC is pruned after the 24h window (SilentDeviceHoursNoMAC), faster than the
// MAC-bearing case.
func TestPruneSilentDevices_NoMAC_24h(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	// Mac-less device offline 25h (> 24h) → pruned.
	insertDevice(t, conn, "old-nomac", "scanner_v2", "offline", "", "10.0.0.3",
		utcPtr(time.Now().Add(-25*time.Hour)))
	// Mac-less device offline 12h (< 24h) → kept.
	insertDevice(t, conn, "recent-nomac", "scanner_v2", "offline", "", "10.0.0.4",
		utcPtr(time.Now().Add(-12*time.Hour)))

	svc := New(queries, nil, nil, conn, config.RetentionConfig{
		SilentDeviceDaysMAC:    7,
		SilentDeviceHoursNoMAC: 24,
		BatchSize:              1000,
	})
	svc.pruneSilentDevices(ctx)

	var remaining int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE name = 'old-nomac'`).Scan(&remaining))
	require.Equal(t, int64(0), remaining, "25h-silent mac-less device must be pruned")
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE name = 'recent-nomac'`).Scan(&remaining))
	require.Equal(t, int64(1), remaining, "12h-silent mac-less device must be kept (< 24h window)")
}

// TestPruneSilentDevices_SkipsManualDevices verifies the scan_source guard: a
// manually-added device (scan_source != 'scanner_v2') is NEVER auto-deleted,
// even if it's been offline for years. This is the CMDB-semantic safety net.
func TestPruneSilentDevices_SkipsManualDevices(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	// A manual device offline for a year with a MAC — must NOT be pruned.
	insertDevice(t, conn, "manual-keep", "manual", "offline", "aa:bb:cc:dd:ee:99", "10.0.0.99",
		utcPtr(time.Now().AddDate(-1, 0, 0)))

	svc := New(queries, nil, nil, conn, config.RetentionConfig{
		SilentDeviceDaysMAC:    7,
		SilentDeviceHoursNoMAC: 24,
		BatchSize:              1000,
	})
	svc.pruneSilentDevices(ctx)

	var remaining int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE name = 'manual-keep'`).Scan(&remaining))
	require.Equal(t, int64(1), remaining, "manual device must never be auto-pruned")
}

// TestPruneSilentDevices_SkipsOnlineDevices verifies an online device is never
// pruned regardless of offline_since (it's online — offline_since should be NULL
// anyway, but this guards the status='offline' filter explicitly).
func TestPruneSilentDevices_SkipsOnlineDevices(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	// Online scanner device with a stale offline_since (shouldn't happen, but
	// defensive) — must be kept because status='online'.
	insertDevice(t, conn, "online-stale", "scanner_v2", "online", "aa:bb:cc:dd:ee:50", "10.0.0.50",
		utcPtr(time.Now().AddDate(0, 0, -30)))

	svc := New(queries, nil, nil, conn, config.RetentionConfig{
		SilentDeviceDaysMAC:    7,
		SilentDeviceHoursNoMAC: 24,
		BatchSize:              1000,
	})
	svc.pruneSilentDevices(ctx)

	require.Equal(t, int64(1), countDevicesWithStatus(t, conn, "online"), "online device must not be pruned")
}

// TestPruneSilentDevices_RoamedOrphan verifies the cross-network migration
// cleanup: a device whose MAC exists ONLINE in another network AND whose
// offline_since is older than the roamed-orphan window is pruned (it's a stale
// old-network leftover — the live copy is elsewhere).
func TestPruneSilentDevices_RoamedOrphan(t *testing.T) {
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
	orphanID := insertDevice(t, conn, "orphan", "scanner_v2", "offline", "aa:bb:cc:dd:ee:77", "10.0.0.77",
		utcPtr(time.Now().Add(-20*time.Minute)))
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net1.ID, orphanID)
	require.NoError(t, err)
	// The live copy: online in net-2, same MAC.
	liveID := insertDevice(t, conn, "live", "scanner_v2", "online", "aa:bb:cc:dd:ee:77", "192.168.2.77", nil)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net2.ID, liveID)
	require.NoError(t, err)

	svc := New(queries, nil, nil, conn, config.RetentionConfig{
		SilentDeviceDaysMAC:    7,
		SilentDeviceHoursNoMAC: 24,
		BatchSize:              1000,
	})
	svc.pruneSilentDevices(ctx)

	var orphanGone int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE id = ?`, orphanID).Scan(&orphanGone))
	require.Equal(t, int64(0), orphanGone, "roamed orphan (MAC online elsewhere, offline > window) must be pruned")
	var liveKept int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE id = ?`, liveID).Scan(&liveKept))
	require.Equal(t, int64(1), liveKept, "the live online copy must be kept")
}

// TestPruneSilentDevices_KeepsRoamedRecent verifies the roamed-orphan prune does
// NOT fire too early: a device whose MAC is online elsewhere but whose
// offline_since is RECENT (< the roamed window) is kept, so an in-progress
// scan/roam can't race the prune.
func TestPruneSilentDevices_KeepsRoamedRecent(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	net1, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "net-1"})
	require.NoError(t, err)
	net2, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "net-2"})
	require.NoError(t, err)

	// Offline only 2min (< 10min roamed window) — kept even though MAC is online elsewhere.
	recentID := insertDevice(t, conn, "recent-orphan", "scanner_v2", "offline", "aa:bb:cc:dd:ee:88", "10.0.0.88",
		utcPtr(time.Now().Add(-2*time.Minute)))
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net1.ID, recentID)
	require.NoError(t, err)
	liveID := insertDevice(t, conn, "live2", "scanner_v2", "online", "aa:bb:cc:dd:ee:88", "192.168.2.88", nil)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET network_id = ? WHERE id = ?`, net2.ID, liveID)
	require.NoError(t, err)

	svc := New(queries, nil, nil, conn, config.RetentionConfig{
		SilentDeviceDaysMAC:    7,
		SilentDeviceHoursNoMAC: 24,
		BatchSize:              1000,
	})
	svc.pruneSilentDevices(ctx)

	var kept int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM devices WHERE id = ?`, recentID).Scan(&kept))
	require.Equal(t, int64(1), kept, "recent-roam orphan (< window) must be kept")
}

// TestPruneSilentDevices_LogsDeviceRemoved verifies each pruned device gets a
// device_removed change_log row (with before snapshot + reason) BEFORE the
// delete, so the audit trail survives the CASCADE.
func TestPruneSilentDevices_LogsDeviceRemoved(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	insertDevice(t, conn, "audited", "scanner_v2", "offline", "aa:bb:cc:dd:ee:33", "10.0.0.33",
		utcPtr(time.Now().AddDate(0, 0, -10)))

	svc := New(queries, nil, nil, conn, config.RetentionConfig{
		SilentDeviceDaysMAC:    7,
		SilentDeviceHoursNoMAC: 24,
		BatchSize:              1000,
	})
	svc.pruneSilentDevices(ctx)

	var n int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT count(*) FROM change_log WHERE change_type = 'device_removed'`).Scan(&n))
	require.Equal(t, int64(1), n, "pruned device must get a device_removed change_log row")
	var reason string
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT agent_id FROM change_log WHERE change_type = 'device_removed' LIMIT 1`).Scan(&reason))
	require.Equal(t, "silent_mac", reason, "change_log agent_id carries the prune reason")
}

// utcPtr returns a pointer to the UTC-normalized time (helper for the
// offlineSince *time.Time params above).
func utcPtr(t time.Time) *time.Time {
	u := t.UTC()
	return &u
}
