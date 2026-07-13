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
	recorder := changedetect.NewDBRecorder(queries, nil, nil)
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
		time.Now().UTC().Add(-10*time.Minute), agentNetID, "192.168.62.41")
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
		time.Now().UTC().Add(-24*time.Hour), centerNetID, "192.168.63.50")
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
		time.Now().UTC().Add(-10*time.Minute), agentNetID, "192.168.62.41")
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
