package runner

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

// setupChangeDetectDB builds an in-memory DB + a runner wired with a real
// DBRecorder so applyDeviceBridge writes change_log. Returns the runner, the
// queries (for direct change_log reads), and the db connection.
func setupChangeDetectDB(t *testing.T) (*Runner, *db.Queries, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	// Seed a network so devices can be tagged.
	net, err := queries.CreateNetwork(context.Background(), db.CreateNetworkParams{Name: "test-net"})
	require.NoError(t, err)
	nid := sql.NullInt64{Int64: net.ID, Valid: true}

	rn := New(nil, queries, conn, nil, 0, nil)
	rn.networkID = nid
	recorder := changedetect.NewDBRecorder(queries, nil, nil)
	rn.SetChangeRecorder(recorder)
	return rn, queries, conn
}

// reportFor builds a minimal HostReport for applyDeviceBridge.
func reportFor(ip, devType, brand, mac string) scannerv2.HostReport {
	return scannerv2.HostReport{
		IP:    ip,
		Alive: true,
		Device: scannerv2.DeviceRef{
			IP:    ip,
			Type:  devType,
			Brand: brand,
			Fields: map[string]string{
				"inferred_type":  devType,
				"inferred_brand": brand,
				"mac":            mac,
			},
		},
	}
}

// TestChangeDetect_NewDeviceEmitsAdded confirms a first-seen device writes a
// device_added row to change_log.
func TestChangeDetect_NewDeviceEmitsAdded(t *testing.T) {
	rn, queries, _ := setupChangeDetectDB(t)
	ctx := context.Background()

	isNew, _ := rn.applyDeviceBridge(ctx, reportFor("10.0.0.5", "camera", "hikvision", "aa:bb:cc:dd:ee:05"), rn.networkID, "")
	require.True(t, isNew, "first sighting should be new")

	events, err := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil,
		Column3: "", ChangeType: "",
		Column5: "", EntityType: "",
		Limit: 100, Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, events, 1, "one device_added event")
	require.Equal(t, "device_added", events[0].ChangeType)
}

// TestChangeDetect_NoChangeNoEvent confirms a rescan that changes NOTHING
// writes zero change_log rows (the wasUpdated-always-true bug is fixed).
func TestChangeDetect_NoChangeNoEvent(t *testing.T) {
	rn, queries, _ := setupChangeDetectDB(t)
	ctx := context.Background()
	rep := reportFor("10.0.0.6", "camera", "hikvision", "aa:bb:cc:dd:ee:06")

	// First scan: creates the device + device_added.
	rn.applyDeviceBridge(ctx, rep, rn.networkID, "")
	// Second scan: identical report — nothing changed.
	_, changed := rn.applyDeviceBridge(ctx, rep, rn.networkID, "")
	require.False(t, changed, "identical rescan should report no change")

	events, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_changed",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, events, 0, "no device_changed event on identical rescan")
}

// TestChangeDetect_TypeChangeEmitsChanged confirms changing a tracked field
// (type) emits a device_changed event with before/after data.
func TestChangeDetect_TypeChangeEmitsChanged(t *testing.T) {
	rn, queries, _ := setupChangeDetectDB(t)
	ctx := context.Background()
	// First scan: camera.
	rn.applyDeviceBridge(ctx, reportFor("10.0.0.7", "camera", "hikvision", "aa:bb:cc:dd:ee:07"), rn.networkID, "")
	// Second scan: SAME MAC, but type reclassified to "server".
	_, changed := rn.applyDeviceBridge(ctx, reportFor("10.0.0.7", "server", "hikvision", "aa:bb:cc:dd:ee:07"), rn.networkID, "")
	require.True(t, changed, "type change should be detected")

	events, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_changed",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, events, 1, "one device_changed event")
	// after_data should carry the type field diff.
	after := events[0].AfterData
	require.NotNil(t, after)
	require.Contains(t, *after, "type")
}

// TestDetectLost_GracePeriod confirms a device absent for 1 scan is NOT lost
// (miss_count=1 < threshold 2), but absent for 2 consecutive scans IS lost
// (status→offline + device_lost event). Devices are created via applyDeviceBridge
// first (DetectLost only updates existing devices + snapshots them).
func TestDetectLost_GracePeriod(t *testing.T) {
	rn, queries, conn := setupChangeDetectDB(t)
	ctx := context.Background()
	netID := rn.networkID

	// Create two devices via applyDeviceBridge (so device rows exist + are online).
	rn.applyDeviceBridge(ctx, reportFor("10.0.0.10", "server", "", "aa:bb:cc:dd:ee:10"), netID, "")
	rn.applyDeviceBridge(ctx, reportFor("10.0.0.11", "server", "", "aa:bb:cc:dd:ee:11"), netID, "")

	// Scan 1: both alive → snapshotted, miss_count=0.
	rn.DetectLost(ctx, netID, 1, []scannerv2.HostReport{
		reportFor("10.0.0.10", "server", "", "aa:bb:cc:dd:ee:10"),
		reportFor("10.0.0.11", "server", "", "aa:bb:cc:dd:ee:11"),
	}, "")

	// Scan 2: only 10.0.0.10. 10.0.0.11 absent once → miss_count=1 < threshold → NOT lost.
	rn.DetectLost(ctx, netID, 1, []scannerv2.HostReport{
		reportFor("10.0.0.10", "server", "", "aa:bb:cc:dd:ee:10"),
	}, "")
	var status11 string
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='10.0.0.11'`).Scan(&status11)
	require.Equal(t, "online", status11, "absent once should NOT be lost (grace period)")
	lostEvents, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_lost",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, lostEvents, 0, "no device_lost after single absence")

	// Scan 3: still only 10.0.0.10. 10.0.0.11 now miss_count=2 >= threshold → LOST.
	rn.DetectLost(ctx, netID, 1, []scannerv2.HostReport{
		reportFor("10.0.0.10", "server", "", "aa:bb:cc:dd:ee:10"),
	}, "")
	conn.QueryRow(`SELECT status FROM devices WHERE ip_address='10.0.0.11'`).Scan(&status11)
	require.Equal(t, "offline", status11, "absent twice should be lost")
	lostEvents, _ = queries.ListChangeLog(ctx, db.ListChangeLogParams{
		Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_lost",
		Column5: 1, EntityType: "device", Limit: 100, Offset: 0,
	})
	require.Len(t, lostEvents, 1, "one device_lost event")

	// Scan 4: 10.0.0.11 reappears → miss_count resets to 0 (no false-lost next time).
	rn.DetectLost(ctx, netID, 1, []scannerv2.HostReport{
		reportFor("10.0.0.11", "server", "", "aa:bb:cc:dd:ee:11"),
	}, "")
	var miss int64
	conn.QueryRow(`SELECT miss_count FROM scan_snapshots WHERE ip='10.0.0.11'`).Scan(&miss)
	require.Equal(t, int64(0), miss, "reappearance resets miss_count")
}

// TestDetectLost_ReappearanceResets confirms a device that comes back before
// crossing the threshold has its miss_count reset (no false lost).
func TestDetectLost_ReappearanceResets(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()
	netID := rn.networkID

	rn.applyDeviceBridge(ctx, reportFor("10.0.0.20", "server", "", "aa:bb:cc:dd:ee:20"), netID, "")
	// Scan 1: alive → snapshotted.
	rn.DetectLost(ctx, netID, 1, []scannerv2.HostReport{
		reportFor("10.0.0.20", "server", "", "aa:bb:cc:dd:ee:20"),
	}, "")
	// Scan 2: absent (miss_count=1).
	rn.DetectLost(ctx, netID, 1, nil, "")
	// Scan 3: reappears (miss_count→0).
	rn.DetectLost(ctx, netID, 1, []scannerv2.HostReport{
		reportFor("10.0.0.20", "server", "", "aa:bb:cc:dd:ee:20"),
	}, "")
	var miss int64
	conn.QueryRow(`SELECT miss_count FROM scan_snapshots WHERE ip='10.0.0.20'`).Scan(&miss)
	require.Equal(t, int64(0), miss, "reappearance after 1 miss resets to 0")
}
