package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestRecordNeighbors_InsertsEdges verifies neighbor edges land in
// device_neighbors after a device exists. RecordNeighbors resolves ip→device_id
// then upserts each neighbor.
func TestRecordNeighbors_InsertsEdges(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.50"

	// Create the device first (RecordNeighbors needs it to resolve device_id).
	require.NoError(t, repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "switch"}))

	neighbors := []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:01", Protocol: "Bridge-MIB", LocalPort: "5"},
		{NeighborMAC: "aa:bb:cc:dd:ee:02", Protocol: "Bridge-MIB", LocalPort: "6"},
	}
	require.NoError(t, repo.RecordNeighbors(ctx, ip, neighbors))

	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM device_neighbors`); cnt != 2 {
		t.Fatalf("expected 2 neighbor rows, got %d", cnt)
	}
}

// TestRecordNeighbors_DedupOnConflict verifies a re-scan upserts (updates
// last_seen) rather than creating duplicate rows.
func TestRecordNeighbors_DedupOnConflict(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	ip := "10.0.0.51"
	repo.RecordDevice(ctx, ip, scannerv2.DeviceRef{IP: ip, Type: "switch"})

	neighbors := []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:03", Protocol: "Bridge-MIB", LocalPort: "7"},
	}
	repo.RecordNeighbors(ctx, ip, neighbors)
	// Re-report the same neighbor — should upsert, not duplicate.
	repo.RecordNeighbors(ctx, ip, neighbors)

	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM device_neighbors WHERE neighbor_mac='aa:bb:cc:dd:ee:03'`); cnt != 1 {
		t.Fatalf("expected 1 row for re-reported neighbor, got %d", cnt)
	}
}

// TestRecordNeighbors_NoDeviceSkips confirms RecordNeighbors is a no-op when the
// device doesn't exist yet (the orchestrator may call before RecordDevice lands).
func TestRecordNeighbors_NoDeviceSkips(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	// No RecordDevice call — device doesn't exist.
	err := repo.RecordNeighbors(ctx, "10.0.0.99", []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:04", Protocol: "Bridge-MIB"},
	})
	require.NoError(t, err, "should not error when device is absent")
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM device_neighbors`); cnt != 0 {
		t.Fatalf("expected 0 rows when device absent, got %d", cnt)
	}
}
