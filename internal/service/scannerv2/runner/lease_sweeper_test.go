package runner

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

// setupLeaseTestDB builds an in-memory DB with TWO networks: a center network
// (agent_id empty) and an agent network (agent_id set). Returns the runner +
// queries + conn + both network ids so tests can assert scope.
func setupLeaseTestDB(t *testing.T) (*Runner, *db.Queries, *sql.DB, int64, int64) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	ctx := context.Background()

	centerNet, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "center-net"})
	require.NoError(t, err)
	agentNet, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "agent-net"})
	require.NoError(t, err)
	// Mark the agent network as agent-managed (CreateNetworkParams has no
	// agent_id field, so set it directly).
	_, err = conn.ExecContext(ctx, `UPDATE networks SET agent_id = 'agent-62' WHERE id = ?`, agentNet.ID)
	require.NoError(t, err)

	rn := New(nil, queries, conn, nil, 0, nil)
	// Identity repo: the lease tests drive applyDeviceBridge with a per-call
	// networkID (center or agent), so the repo's own NetworkID is unused by the
	// identity methods (they take the per-call value).
	rn.SetRepo(store.NewSQLiteRepository(conn, store.Options{}, nil))
	recorder := changedetect.NewDBRecorder(queries, nil, 0, nil)
	rn.SetChangeRecorder(recorder)
	return rn, queries, conn, centerNet.ID, agentNet.ID
}

// TestLeaseSweeper_LeaseRefreshedOnReport confirms that an agent report
// refreshes the snapshot's last_seen_at (via RecordAliveSnapshots) so a device
// the agent keeps reporting never goes stale.
func TestLeaseSweeper_LeaseRefreshedOnReport(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}

	// Create a device on the agent network + snapshot it.
	rn.applyDeviceBridge(ctx, reportFor("192.168.62.41", "camera", "hikvision", "aa:bb:cc:dd:ee:41"), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor("192.168.62.41", "camera", "hikvision", "aa:bb:cc:dd:ee:41"),
	})

	// Sweep with a generous TTL — device was just seen, should NOT expire.
	sweeper := NewLeaseSweeper(rn, time.Hour, time.Hour, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.62.41'`).Scan(&status)
	require.Equal(t, "online", status, "freshly-reported device must not expire")
	lost, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_lost",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, lost, 0, "no device_lost for a fresh device")
}

// TestLeaseSweeper_ExpiresStaleAgentDevice confirms a stale snapshot in an
// agent network (last_seen_at old) is expired: status→offline + device_lost.
func TestLeaseSweeper_ExpiresStaleAgentDevice(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}

	// Create the device + its snapshot (applyDeviceBridge makes the device row;
	// RecordAliveSnapshots makes the snapshot row the sweeper reads).
	rn.applyDeviceBridge(ctx, reportFor("192.168.62.41", "camera", "hikvision", "aa:bb:cc:dd:ee:41"), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor("192.168.62.41", "camera", "hikvision", "aa:bb:cc:dd:ee:41"),
	})
	// Backdate the snapshot so it's past the TTL.
	_, err := conn.ExecContext(ctx,
		`UPDATE scan_snapshots SET last_seen_at = ? WHERE network_id = ? AND ip = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-10*time.Minute)), agentNetID, "192.168.62.41")
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.62.41'`).Scan(&status)
	require.Equal(t, "offline", status, "stale agent device should be expired")
	lost, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_lost",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, lost, 1, "one device_lost event emitted")
}

// TestLeaseSweeper_IgnoresCenterNetwork confirms the sweeper does NOT touch
// the center's own network even if a snapshot there is ancient (those are the
// local-scan DetectLost path's responsibility).
func TestLeaseSweeper_IgnoresCenterNetwork(t *testing.T) {
	rn, queries, conn, centerNetID, _ := setupLeaseTestDB(t)
	ctx := context.Background()
	cnid := sql.NullInt64{Int64: centerNetID, Valid: true}

	// Device on the center network with an ancient snapshot.
	rn.applyDeviceBridge(ctx, reportFor("192.168.63.50", "server", "", "aa:bb:cc:dd:ee:50"), cnid, "")
	rn.RecordAliveSnapshots(ctx, cnid, 0, []scannerv2.HostReport{
		reportFor("192.168.63.50", "server", "", "aa:bb:cc:dd:ee:50"),
	})
	_, err := conn.ExecContext(ctx,
		`UPDATE scan_snapshots SET last_seen_at = ? WHERE network_id = ? AND ip = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-24*time.Hour)), centerNetID, "192.168.63.50")
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.63.50'`).Scan(&status)
	require.Equal(t, "online", status, "center-network device must not be expired by the lease sweeper")
	lost, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_lost",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, lost, 0, "no device_lost for center-network devices")
}

// TestLeaseSweeper_IgnoresAlreadyOffline confirms a stale device already marked
// offline is not re-emitted (the status='online' filter in the stale query).
func TestLeaseSweeper_IgnoresAlreadyOffline(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}

	rn.applyDeviceBridge(ctx, reportFor("192.168.62.41", "camera", "hikvision", "aa:bb:cc:dd:ee:41"), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor("192.168.62.41", "camera", "hikvision", "aa:bb:cc:dd:ee:41"),
	})
	// Make it stale AND already offline.
	_, err := conn.ExecContext(ctx,
		`UPDATE scan_snapshots SET last_seen_at = ? WHERE network_id = ? AND ip = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-10*time.Minute)), agentNetID, "192.168.62.41")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`UPDATE devices SET status = 'offline' WHERE ip_address = '192.168.62.41'`)
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	lost, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_lost",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, lost, 0, "already-offline device must not be re-emitted")
}

// TestLeaseSweeper_RecoversFreshOfflineAgentDevice is the symmetric counterpart
// of TestLeaseSweeper_ExpiresStaleAgentDevice: a device the sweeper previously
// marked offline, whose snapshot lease is now FRESH again (the agent resumed
// reporting it), must be flipped back online — closing the recovery gap the
// stable-hash fast path (agent_report.go) opens, where leases refresh but the
// devices row is never touched. The recovery emits a device_recovered event (the
// symmetric counterpart of device_lost), NOT device_changed — status is a
// liveness signal, excluded from the identity-diff gate.
func TestLeaseSweeper_RecoversFreshOfflineAgentDevice(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}

	// Create the device + a FRESH snapshot (RecordAliveSnapshots stamps now).
	rn.applyDeviceBridge(ctx, reportFor("192.168.62.41", "pc", "", "aa:bb:cc:dd:ee:41"), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor("192.168.62.41", "pc", "", "aa:bb:cc:dd:ee:41"),
	})
	// Simulate the stuck state: the sweeper marked it offline earlier, but the
	// agent is actively reporting it alive again (snapshot stays fresh).
	_, err := conn.ExecContext(ctx,
		`UPDATE devices SET status = 'offline' WHERE ip_address = '192.168.62.41'`)
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.62.41'`).Scan(&status)
	require.Equal(t, "online", status, "fresh-lease agent device stuck offline should be recovered")

	// Recovery emits device_recovered (offline→online), not device_changed.
	recovered, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_recovered",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, recovered, 1, "one device_recovered event emitted")
	// And NO device_changed from the status flip (status is excluded from the
	// identity gate).
	changed, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_changed",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, changed, 0, "recovery must not emit device_changed (status is not an identity field)")
}

// TestLeaseSweeper_NoRecoverOnCenterNetwork confirms the recovery path — like
// the expiry path — is scoped to agent networks only. A center-network device
// that is offline with a fresh snapshot must NOT be touched by the sweeper
// (the center has its own applyDeviceBridge recovery path via local scans).
func TestLeaseSweeper_NoRecoverOnCenterNetwork(t *testing.T) {
	rn, _, conn, centerNetID, _ := setupLeaseTestDB(t)
	ctx := context.Background()
	cnid := sql.NullInt64{Int64: centerNetID, Valid: true}

	rn.applyDeviceBridge(ctx, reportFor("192.168.63.50", "server", "", "aa:bb:cc:dd:ee:50"), cnid, "")
	rn.RecordAliveSnapshots(ctx, cnid, 0, []scannerv2.HostReport{
		reportFor("192.168.63.50", "server", "", "aa:bb:cc:dd:ee:50"),
	})
	// Offline but fresh lease — the recovery candidate shape, on the CENTER net.
	_, err := conn.ExecContext(ctx,
		`UPDATE devices SET status = 'offline' WHERE ip_address = '192.168.63.50'`)
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.63.50'`).Scan(&status)
	require.Equal(t, "offline", status, "center-network device must not be recovered by the lease sweeper")
}

// TestLeaseSweeper_StopWaitsForGoroutine verifies the shutdown contract (#163):
// after Stop() returns, the sweep goroutine has fully exited. We cancel the ctx
// (which the loop selects on) then call Stop() — if Stop() did NOT wait (the
// pre-fix bug), the goroutine could still be running and race setupLeaseTestDB's
// t.Cleanup conn.Close(). The race detector makes this definitive: a leaked
// goroutine touching conn after the cleanup close trips a data race.
func TestLeaseSweeper_StopWaitsForGoroutine(t *testing.T) {
	rn, _, _, _, _ := setupLeaseTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())

	sweeper := NewLeaseSweeper(rn, 50*time.Millisecond, 5*time.Minute, nil)
	sweeper.Start(ctx)

	// Let at least one tick fire so the goroutine is actively sweeping.
	time.Sleep(120 * time.Millisecond)

	cancel()
	sweeper.Stop() // must block until the goroutine exits before t.Cleanup closes conn
}

// seedOrphan creates the #397 legacy shape: a device row bridged from an agent
// report whose snapshot lease row has since vanished (what the pre-#389 lease
// mis-resolution left behind once its lease feeder moved to the correct asset),
// with the device row's last_seen aged past the given duration. The device row
// keeps its uuid — only the lease reference is gone.
func seedOrphan(t *testing.T, rn *Runner, conn *sql.DB, networkID int64, ip, mac string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	nid := sql.NullInt64{Int64: networkID, Valid: true}
	rn.applyDeviceBridge(ctx, reportFor(ip, "pc", "", mac), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{reportFor(ip, "pc", "", mac)})
	_, err := conn.ExecContext(ctx, `DELETE FROM scan_snapshots WHERE network_id = ? AND ip = ?`, networkID, ip)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE ip_address = ? AND network_id = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-age)), ip, networkID)
	require.NoError(t, err)
}

// listLost lists change_log device_lost rows (the shared assertion helper shape
// used throughout this file).
func listLost(t *testing.T, queries *db.Queries) []db.ChangeLog {
	t.Helper()
	lost, err := queries.ListChangeLog(context.Background(), db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_lost",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.NoError(t, err)
	return lost
}

// TestLeaseSweeper_ExpiresOrphanedAgentDevice (#397): an online scanner-discovered
// device in an agent network whose last_seen is past the TTL and which NO
// scan_snapshots row references is invisible to the stale/recover queries (both
// walk FROM snapshots and would never find it). The orphan backstop must flip it
// offline, emit device_lost, and stamp offline_since for the retention sweep.
// The flip is terminal — a second sweep must not re-emit.
func TestLeaseSweeper_ExpiresOrphanedAgentDevice(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	seedOrphan(t, rn, conn, agentNetID, "192.168.62.71", "aa:bb:cc:dd:ee:71", 10*time.Minute)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status, offlineSince string
	conn.QueryRow(`SELECT status, COALESCE(offline_since,'') FROM devices WHERE ip_address='192.168.62.71'`).Scan(&status, &offlineSince)
	require.Equal(t, "offline", status, "orphaned online device must be expired by the backstop")
	require.NotEmpty(t, offlineSince, "offline_since must be stamped for the retention sweep")
	require.Len(t, listLost(t, queries), 1, "one device_lost event emitted for the orphan")

	// Terminal: the status='online' filter means the orphan fires at most once
	// (there is no snapshot row to carry a flap counter — none is needed).
	sweeper.sweepOnce(ctx)
	require.Len(t, listLost(t, queries), 1, "orphan flip must not re-emit on the next sweep")
}

// TestLeaseSweeper_OrphanProtectedWithinTTL: the last_seen < cutoff guard — a
// recently-seen orphan (e.g. a row bridged moments ago whose snapshot upsert
// hasn't landed) must survive a full TTL window before the backstop fires.
func TestLeaseSweeper_OrphanProtectedWithinTTL(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	seedOrphan(t, rn, conn, agentNetID, "192.168.62.72", "aa:bb:cc:dd:ee:72", time.Minute)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.62.72'`).Scan(&status)
	require.Equal(t, "online", status, "orphan within the TTL window must not be expired")
}

// TestLeaseSweeper_LeaseReferencedDeviceNotOrphanExpired: the NOT EXISTS guard —
// a device whose uuid IS referenced by a snapshot (even with an aged device-row
// last_seen) belongs to the normal stale/recover paths, never the orphan
// backstop. With a FRESH lease it must stay online untouched.
func TestLeaseSweeper_LeaseReferencedDeviceNotOrphanExpired(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	ip, mac := "192.168.62.73", "aa:bb:cc:dd:ee:73"
	rn.applyDeviceBridge(ctx, reportFor(ip, "pc", "", mac), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{reportFor(ip, "pc", "", mac)})
	// Age the DEVICE row only; the lease stays fresh → not an orphan, not stale.
	_, err := conn.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE ip_address = ? AND network_id = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-10*time.Minute)), ip, agentNetID)
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address=?`, ip).Scan(&status)
	require.Equal(t, "online", status, "lease-referenced device with a fresh lease must stay online")
}

// TestLeaseSweeper_OrphanIgnoresManualDevices: manual devices are user
// assertions, not lease subjects — an online manual device in an agent network
// with an ancient last_seen and no snapshot must never be flipped by the
// backstop (mirrors the retention sweep's scan_source convention).
func TestLeaseSweeper_OrphanIgnoresManualDevices(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	_, err := conn.ExecContext(ctx, `
		INSERT INTO devices (name, type, status, ip_address, mac_address, network_id, scan_source, last_seen)
		VALUES ('manual-box', 'other', 'online', '192.168.62.99', 'aa:bb:cc:dd:ee:99', ?, 'manual', ?)`,
		agentNetID, scannerv2.DBTime(time.Now().UTC().Add(-24*time.Hour)))
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.62.99'`).Scan(&status)
	require.Equal(t, "online", status, "manual device must not be expired by the orphan backstop")
}

// TestLeaseSweeper_OrphanIgnoredOnCenterNetwork: like both other directions, the
// orphan backstop is scoped to agent networks — the center's own network keeps
// its local-scan DetectLost + heartbeat paths.
func TestLeaseSweeper_OrphanIgnoredOnCenterNetwork(t *testing.T) {
	rn, _, conn, centerNetID, _ := setupLeaseTestDB(t)
	ctx := context.Background()
	seedOrphan(t, rn, conn, centerNetID, "192.168.63.71", "aa:bb:cc:dd:ee:71", 10*time.Minute)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='192.168.63.71'`).Scan(&status)
	require.Equal(t, "online", status, "center-network orphan must not be expired by the lease sweeper")
}

// TestLeaseSweeper_OrphanRecoversWhenReportedAgain closes the lifecycle loop:
// after the backstop flips an orphan offline, the agent reporting the host again
// re-creates its snapshot (MAC-primary uuid resolution, #395) and recoverFresh
// flips the row back online with a device_recovered event.
func TestLeaseSweeper_OrphanRecoversWhenReportedAgain(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	ip, mac := "192.168.62.74", "aa:bb:cc:dd:ee:74"
	seedOrphan(t, rn, conn, agentNetID, ip, mac, 10*time.Minute)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)
	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address=?`, ip).Scan(&status)
	require.Equal(t, "offline", status, "precondition: orphan expired")

	// The agent reports the host again — lease re-created, row still offline.
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{reportFor(ip, "pc", "", mac)})
	sweeper.sweepOnce(ctx)

	conn.QueryRow(`SELECT status FROM devices WHERE ip_address=?`, ip).Scan(&status)
	require.Equal(t, "online", status, "re-reported orphan must recover via its fresh lease")
	recovered, err := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_recovered",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, recovered, 1, "one device_recovered event emitted")
}

// seedRoamedDevice creates the #399 shape: one device row holding TWO lease
// rows in the agent network — the pre-roam IP (aged past the TTL) and the
// post-roam IP (fresh), both stamped with the device's uuid. Returns the uuid.
func seedRoamedDevice(t *testing.T, rn *Runner, conn *sql.DB, agentNetID int64, oldIP, newIP, mac string, oldAge time.Duration) string {
	t.Helper()
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	// The device row + its ORIGINAL lease at the old IP.
	rn.applyDeviceBridge(ctx, reportFor(oldIP, "pc", "", mac), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{reportFor(oldIP, "pc", "", mac)})
	var uuid string
	require.NoError(t, conn.QueryRow(`SELECT device_uuid FROM devices WHERE ip_address=? AND network_id=?`, oldIP, agentNetID).Scan(&uuid))
	require.NotEmpty(t, uuid)
	// Roam: the device now lives at newIP — a fresh lease row there (the bridge
	// would have moved the device row's ip too; only the lease shape matters
	// here, so hand-write the snapshot).
	_, err := conn.ExecContext(ctx, `
		INSERT INTO scan_snapshots (network_id, task_id, ip, mac, device_uuid, miss_count, last_seen_at)
		VALUES (?, NULL, ?, ?, ?, 0, ?)`,
		agentNetID, newIP, mac, uuid, scannerv2.DBTime(time.Now().UTC()))
	require.NoError(t, err)
	// Age the pre-roam lease past the TTL.
	_, err = conn.ExecContext(ctx, `UPDATE scan_snapshots SET last_seen_at = ? WHERE network_id = ? AND ip = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-oldAge)), agentNetID, oldIP)
	require.NoError(t, err)
	// The bridge moves the device row's IP on a roam — mirror that, so the
	// dissociated remnant (empty uuid) can't re-match the device via the IP
	// fallback join at its OLD address.
	_, err = conn.ExecContext(ctx, `UPDATE devices SET ip_address = ? WHERE device_uuid = ?`, newIP, uuid)
	require.NoError(t, err)
	return uuid
}

// TestLeaseSweeper_RoamRemnantSkippedAndDissociated (#399): a device that
// DHCP-roamed holds a stale pre-roam lease AND a fresh post-roam lease, both
// keyed to its uuid. The stale remnant must NOT kill the device — it is alive
// at its new IP. The remnant is dissociated (device_uuid cleared) so it can
// never judge the device again; the fresh lease keeps referencing it.
func TestLeaseSweeper_RoamRemnantSkippedAndDissociated(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	uuid := seedRoamedDevice(t, rn, conn, agentNetID, "192.168.63.145", "192.168.63.172", "11:22:33:44:55:66", 30*time.Minute)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE device_uuid=?`, uuid).Scan(&status)
	require.Equal(t, "online", status, "roamed device with a fresh lease must not be expired by its stale pre-roam remnant")
	require.Len(t, listLost(t, queries), 0, "no device_lost for a roamed-alive device")
	var remnantUUID string
	conn.QueryRow(`SELECT COALESCE(device_uuid,'') FROM scan_snapshots WHERE network_id=? AND ip='192.168.63.145'`, agentNetID).Scan(&remnantUUID)
	require.Empty(t, remnantUUID, "pre-roam remnant must be dissociated (device_uuid cleared)")
	var freshUUID string
	conn.QueryRow(`SELECT device_uuid FROM scan_snapshots WHERE network_id=? AND ip='192.168.63.172'`, agentNetID).Scan(&freshUUID)
	require.Equal(t, uuid, freshUUID, "post-roam lease keeps referencing the device")

	// Steady state: the next sweep finds no stale row for the device at all
	// (the remnant is unattributed) — no expiry, no dissociation repeat.
	sweeper.sweepOnce(ctx)
	require.Len(t, listLost(t, queries), 0, "no further events after the remnant is dissociated")
}

// TestLeaseSweeper_DeadDeviceWithMultipleLeasesStillExpires: the roam guard
// must not shield a device whose leases are ALL stale — that device is really
// gone (it roamed once, then left). The normal expiry path fires.
func TestLeaseSweeper_DeadDeviceWithMultipleLeasesStillExpires(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	uuid := seedRoamedDevice(t, rn, conn, agentNetID, "192.168.63.145", "192.168.63.172", "11:22:33:44:55:66", 30*time.Minute)
	// Kill the post-roam lease too — nothing fresh anywhere.
	_, err := conn.ExecContext(ctx, `UPDATE scan_snapshots SET last_seen_at = ? WHERE device_uuid = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-30*time.Minute)), uuid)
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE device_uuid=?`, uuid).Scan(&status)
	require.Equal(t, "offline", status, "device with no fresh lease anywhere must still expire")
	require.Len(t, listLost(t, queries), 1, "one device_lost emitted")
}

// TestLeaseSweeper_CrossNetworkFreshLeaseDoesNotBlockExpiry: the roam guard is
// network-scoped — a fresh lease for the same asset in ANOTHER network means
// the asset moved networks; this network's device row must still expire.
func TestLeaseSweeper_CrossNetworkFreshLeaseDoesNotBlockExpiry(t *testing.T) {
	rn, queries, conn, centerNetID, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	uuid := seedRoamedDevice(t, rn, conn, agentNetID, "192.168.63.145", "192.168.63.172", "11:22:33:44:55:66", 30*time.Minute)
	// Make BOTH agent-net leases stale, then plant a fresh same-uuid lease in the
	// CENTER network (the asset moved there).
	_, err := conn.ExecContext(ctx, `UPDATE scan_snapshots SET last_seen_at = ? WHERE device_uuid = ?`,
		scannerv2.DBTime(time.Now().UTC().Add(-30*time.Minute)), uuid)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `
		INSERT INTO scan_snapshots (network_id, task_id, ip, mac, device_uuid, miss_count, last_seen_at)
		VALUES (?, NULL, '192.168.62.200', '11:22:33:44:55:66', ?, 0, ?)`,
		centerNetID, uuid, scannerv2.DBTime(time.Now().UTC()))
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var status string
	conn.QueryRow(`SELECT status FROM devices WHERE device_uuid=?`, uuid).Scan(&status)
	require.Equal(t, "offline", status, "cross-network fresh lease must not block this network's expiry")
	require.Len(t, listLost(t, queries), 1, "one device_lost emitted")
}

// TestLeaseSweeper_FlapDecayAfterStablePeriod: flap_count halves once the last
// flap is older than the stable period — independent of any liveness
// transition (a device that stops flapping stays online and never passes
// through recoverFresh, the only other decay site). A recent flap does not
// decay; the halving refreshes last_flap_at so each halving needs a fresh full
// stable window.
func TestLeaseSweeper_FlapDecayAfterStablePeriod(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	rn.applyDeviceBridge(ctx, reportFor("192.168.63.161", "pc", "", "aa:bb:cc:dd:ee:61"), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{reportFor("192.168.63.161", "pc", "", "aa:bb:cc:dd:ee:61")})
	// A quiet flapper (last flap long ago) and a recent one.
	_, err := conn.ExecContext(ctx, `UPDATE scan_snapshots SET flap_count = 8, last_flap_at = ? WHERE ip = '192.168.63.161'`,
		scannerv2.DBTime(time.Now().UTC().Add(-2*flapStablePeriod)))
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `
		INSERT INTO scan_snapshots (network_id, task_id, ip, mac, device_uuid, miss_count, last_seen_at, flap_count, last_flap_at)
		VALUES (?, NULL, '192.168.63.162', '', '', 0, ?, 6, ?)`,
		agentNetID, scannerv2.DBTime(time.Now().UTC()), scannerv2.DBTime(time.Now().UTC().Add(-time.Minute)))
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, 5*time.Minute, nil)
	sweeper.sweepOnce(ctx)

	var quietFlap int64
	var quietAt string
	conn.QueryRow(`SELECT flap_count, last_flap_at FROM scan_snapshots WHERE ip='192.168.63.161'`).Scan(&quietFlap, &quietAt)
	require.Equal(t, int64(4), quietFlap, "quiet flapper's counter must halve (8→4)")
	require.NotEmpty(t, quietAt, "last_flap_at refreshed — each halving needs a new stable window")
	var recentFlap int64
	conn.QueryRow(`SELECT flap_count FROM scan_snapshots WHERE ip='192.168.63.162'`).Scan(&recentFlap)
	require.Equal(t, int64(6), recentFlap, "recent flap must not decay")
}
