package store

import (
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

	// First scan: device discovered with MAC, no os_type yet.
	d1 := scannerv2.DeviceRef{
		IP:    ip,
		Type:  "server",
		Brand: "",
		Fields: map[string]string{
			"mac": mac,
		},
	}
	if err := repo.RecordDevice(ctx, ip, d1); err != nil {
		t.Fatalf("record device (insert): %v", err)
	}

	// Second scan: SSH banner classified, SSHHandler set os_type=Windows in
	// Device.Fields. The re-scan carries the same MAC.
	d2 := scannerv2.DeviceRef{
		IP:    ip,
		Type:  "server",
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

// TestRecordDevice_OSType_WithCrossNetworkDuplicate reproduces the EXACT
// production scenario: a device was previously discovered by an agent on
// network_id=3 (no MAC → separate row), then the center (network_id=1)
// discovers the same IP WITH a MAC. The center scan should create/update its
// own row with os_type, and the stale network_id=3 row should NOT interfere.
//
// In production, .9 had id=49 (network_id=1, MAC) + id=62 (network_id=3, no MAC).
// The center scan didn't update id=49's scan_attributes. This test checks whether
// that's a store-layer bug or something upstream.
func TestRecordDevice_OSType_WithCrossNetworkDuplicate(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	ip := "192.168.63.9"

	// Simulate an agent report that created a network_id=3 row (no MAC).
	// We can't use Options{NetworkID:3} for one call, so insert directly.
	_, err := repo.db.ExecContext(ctx, `
		INSERT INTO devices (name, type, ip_address, mac_address, status, scan_source,
		                     scan_attributes, network_id, first_seen, last_seen,
		                     last_scanned_at, created_at, updated_at)
		VALUES ('.9', 'server', ?, '', 'unknown', 'scanner_v2',
		        '{}', 3, '2026-07-09 04:00:00', '2026-07-09 04:00:00',
		        '2026-07-09 04:39:52', '2026-07-09 04:00:00', '2026-07-09 04:00:00')`, ip)
	if err != nil {
		t.Fatalf("seed network_id=3 row: %v", err)
	}

	// Center scan: discovers .9 with MAC + os_type (from SSH classifier).
	mac := "04:7c:16:19:22:0e"
	d := scannerv2.DeviceRef{
		IP:    ip,
		Type:  "server",
		Fields: map[string]string{
			"mac":     mac,
			"os_type": "Windows",
		},
	}
	if err := repo.RecordDevice(ctx, ip, d); err != nil {
		t.Fatalf("record device (center scan): %v", err)
	}

	// The center row (MAC match) should have os_type in scan_attributes.
	var scanAttrs string
	if err := repo.db.QueryRow(`SELECT scan_attributes FROM devices WHERE mac_address=?`, mac).Scan(&scanAttrs); err != nil {
		// If this fails, the MAC row wasn't created/found — that's the bug.
		t.Fatalf("MAC row not found after center scan: %v", err)
	}
	var attr map[string]any
	if err := json.Unmarshal([]byte(scanAttrs), &attr); err != nil {
		t.Fatalf("unmarshal: %v (raw=%q)", err, scanAttrs)
	}
	if attr["os"] != "Windows" {
		t.Errorf("scan_attributes.os = %v, want Windows", attr["os"])
	}

	// Count rows: should be 2 (network_id=3 stale + network_id=1 fresh with MAC).
	var count int
	if err := repo.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address=?`, ip).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2 rows (stale + fresh), got %d", count)
	}
	t.Logf("rows=%d, os=%v", count, attr["os"])
}
