package store

import (
	"database/sql"
	"encoding/json"
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

// TestRecordDevice_OSType_Propagation reproduces the .9 Windows bug: a device
// discovered earlier (with a MAC) gets re-scanned, the re-scan carries
// os_type in DeviceRef.Fields, and scan_attributes.os must be populated.
//
// This is the exact path that was failing in production: the classifier
// emitted os_type=Windows, the SSHHandler propagated it to Device.Fields, but
// scan_attributes.os stayed empty on the device row.
func TestRecordDevice_OSType_Propagation(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	ip := "192.168.63.9"
	mac := "04:7c:16:19:22:0e"

	// Seed the device row (RecordDevice no longer creates identities).
	seedDeviceRow(t, repo.db, ip, mac, sql.NullInt64{Int64: 1, Valid: true})

	// Second scan: SSH banner classified, SSHHandler set os_type=Windows in
	// Device.Fields. The re-scan carries the same MAC.
	d2 := scannerv2.DeviceRef{
		IP:   ip,
		Type: "server",
		Fields: map[string]string{
			"mac":     mac,
			"os_type": "Windows",
		},
	}
	if err := repo.RecordDevice(ctx, ip, d2); err != nil {
		t.Fatalf("record device (update): %v", err)
	}

	// Verify scan_attributes.os is populated.
	var scanAttrs string
	if err := repo.db.QueryRow(`SELECT scan_attributes FROM devices WHERE mac_address=?`, mac).Scan(&scanAttrs); err != nil {
		t.Fatalf("query device: %v", err)
	}
	var attr map[string]any
	if err := json.Unmarshal([]byte(scanAttrs), &attr); err != nil {
		t.Fatalf("unmarshal scan_attributes: %v (raw=%q)", err, scanAttrs)
	}
	if attr["os"] != "Windows" {
		t.Errorf("scan_attributes.os = %v, want Windows (full attr: %v)", attr["os"], attr)
	}

	// Also verify last_scanned_at was updated (the symptom was a stale row).
	var lastScanned string
	if err := repo.db.QueryRow(`SELECT last_scanned_at FROM devices WHERE mac_address=?`, mac).Scan(&lastScanned); err != nil {
		t.Fatal(err)
	}
	if lastScanned == "" {
		t.Error("last_scanned_at is empty after update")
	}
	t.Logf("scan_attributes.os = %v, last_scanned_at = %s", attr["os"], lastScanned)
}

// TestRecordDevice_OSType_WithCrossNetworkDuplicate verifies the single-writer
// contract across networks: an agent-discovered row on network_id=3 (no MAC)
// and a center-discovered MAC row are TWO distinct assets. RecordDevice enriches
// the MAC-matched row (global match) with os_type; it does NOT touch the
// network_id=3 row (different identity) and does NOT create new rows.
//
// Previously this test asserted the store would create the MAC row; under the
// single-writer design the store only enriches, so we seed the MAC row (as the
// runner would) and assert os_type propagation into scan_attributes.
func TestRecordDevice_OSType_WithCrossNetworkDuplicate(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	ip := "192.168.63.9"
	mac := "04:7c:16:19:22:0e"

	// Agent-discovered row on network_id=3 (no MAC) — a distinct asset.
	_, err := repo.db.ExecContext(ctx, `
		INSERT INTO devices (name, type, ip_address, mac_address, status, scan_source,
		                     scan_attributes, network_id, device_uuid, first_seen, last_seen,
		                     last_scanned_at, created_at, updated_at)
		VALUES ('.9', 'server', ?, '', 'unknown', 'scanner_v2',
		        '{}', 3, ?, '2026-07-09 04:00:00', '2026-07-09 04:00:00',
		        '2026-07-09 04:39:52', '2026-07-09 04:00:00', '2026-07-09 04:00:00')`, ip, "seed-net3-"+ip)
	if err != nil {
		t.Fatalf("seed network_id=3 row: %v", err)
	}
	// Center-discovered MAC row (network_id=1) — the asset the center owns.
	seedDeviceRow(t, repo.db, ip, mac, sql.NullInt64{Int64: 1, Valid: true})

	// Center re-scan: discovers .9 with MAC + os_type (from SSH classifier).
	d := scannerv2.DeviceRef{
		IP:   ip,
		Type: "server",
		Fields: map[string]string{
			"mac":     mac,
			"os_type": "Windows",
		},
	}
	if err := repo.RecordDevice(ctx, ip, d); err != nil {
		t.Fatalf("record device (center scan): %v", err)
	}

	// The MAC row (center) is enriched with os_type in scan_attributes.
	var scanAttrs string
	if err := repo.db.QueryRow(`SELECT scan_attributes FROM devices WHERE mac_address=?`, mac).Scan(&scanAttrs); err != nil {
		t.Fatalf("MAC row not found after enrich: %v", err)
	}
	var attr map[string]any
	if err := json.Unmarshal([]byte(scanAttrs), &attr); err != nil {
		t.Fatalf("unmarshal: %v (raw=%q)", err, scanAttrs)
	}
	if attr["os"] != "Windows" {
		t.Errorf("scan_attributes.os = %v, want Windows", attr["os"])
	}

	// Still exactly two rows — the agent row (network_id=3, untouched) and the
	// center MAC row (enriched). RecordDevice did not create a third.
	var count int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address=?`, ip).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2 rows (agent + center, no new), got %d", count)
	}
}
