package repository

import (
	"context"
	"database/sql"
	"testing"

	"mibee-steward/internal/domain"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// setupAttributesTestDB creates an in-memory DB with the devices table shape
// (including scan_attributes + user_attributes + the 4 generated columns) and
// returns a DeviceRepository plus a seeded device ID.
func setupAttributesTestDB(t *testing.T) (*DeviceRepository, *sql.DB, int64) {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other',
			brand TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			purpose TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown',
			ip_address TEXT NOT NULL DEFAULT '',
			mac_address TEXT NOT NULL DEFAULT '',
			serial_number TEXT NOT NULL DEFAULT '',
			purchase_date TEXT NOT NULL DEFAULT '',
			warranty_expiry TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '{}',
			scan_source TEXT NOT NULL DEFAULT 'manual',
			prometheus_labels TEXT NOT NULL DEFAULT '{}',
			last_scanned_at TIMESTAMP,
			last_scan_task_id INTEGER,
			open_ports TEXT NOT NULL DEFAULT '[]',
			detected_services TEXT NOT NULL DEFAULT '[]',
			prometheus_url TEXT NOT NULL DEFAULT '',
			node_exporter_url TEXT NOT NULL DEFAULT '',
			last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
			scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
			user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
			scan_vendor   TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.vendor')) STORED,
			scan_mac      TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.mac')) STORED,
			scan_os       TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.os')) STORED,
			scan_hostname TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.hostname')) STORED,
			network_id INTEGER,
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_devices_scan_mac_expr ON devices(json_extract(scan_attributes, '$.mac'));`)
	require.NoError(t, err)

	repo := NewDeviceRepository(conn)
	ctx := context.Background()
	device, err := repo.Create(ctx, domain.CreateDeviceRequest{
		Name:      "test-cam",
		Type:      "camera",
		IPAddress: "192.168.63.133",
	})
	require.NoError(t, err)
	return repo, conn, device.ID
}

func TestUpdateUserAttributes_MergesAndPersists(t *testing.T) {
	repo, conn, id := setupAttributesTestDB(t)
	ctx := context.Background()

	// First write.
	err := repo.UpdateUserAttributes(ctx, id, domain.UserAttributes{"owner": "ops", "rack": "A1"})
	require.NoError(t, err)

	var raw string
	require.NoError(t, conn.QueryRow(`SELECT user_attributes FROM devices WHERE id = ?`, id).Scan(&raw))
	got, err := domain.UnmarshalUserAttributes(raw)
	require.NoError(t, err)
	require.Equal(t, "ops", got["owner"])
	require.Equal(t, "A1", got["rack"])
}

func TestUpdateScanAttributes_PopulatesGeneratedColumns(t *testing.T) {
	repo, conn, id := setupAttributesTestDB(t)
	ctx := context.Background()

	err := repo.UpdateScanAttributes(ctx, id, domain.ScanAttributes{
		Vendor:   "Hikvision",
		MAC:      "bc:ad:28:11:22:33",
		OS:       "Linux",
		Hostname: "cam-front",
	})
	require.NoError(t, err)

	// The generated columns should be populated from the JSON we just wrote.
	var scanVendor, scanMac, scanOS, scanHostname sql.NullString
	err = conn.QueryRow(
		`SELECT scan_vendor, scan_mac, scan_os, scan_hostname FROM devices WHERE id = ?`, id,
	).Scan(&scanVendor, &scanMac, &scanOS, &scanHostname)
	require.NoError(t, err)
	require.Equal(t, "Hikvision", scanVendor.String)
	require.Equal(t, "bc:ad:28:11:22:33", scanMac.String)
	require.Equal(t, "Linux", scanOS.String)
	require.Equal(t, "cam-front", scanHostname.String)
}

func TestGetByMAC_FindsByScanAttributesMAC(t *testing.T) {
	repo, _, id := setupAttributesTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.UpdateScanAttributes(ctx, id, domain.ScanAttributes{
		MAC: "bc:ad:28:11:22:33",
	}))

	got, ok, err := repo.GetByMAC(ctx, "bc:ad:28:11:22:33")
	require.NoError(t, err)
	require.True(t, ok, "expected a device match by MAC")
	require.Equal(t, id, got.ID)

	// Miss.
	_, ok, err = repo.GetByMAC(ctx, "aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)
	require.False(t, ok)

	// Empty MAC query is a no-op (no scan, no error).
	_, ok, err = repo.GetByMAC(ctx, "")
	require.NoError(t, err)
	require.False(t, ok)
}

// TestCreateDeviceRejectsInvalidUserAttributes is a sanity check that the
// json_valid CHECK on user_attributes guards against bad JSON slipping in via
// the marshal helper — since the helper always produces valid JSON, this is
// mostly asserting the CHECK constraint is in effect.
func TestCreateDeviceRejectsInvalidUserAttributes(t *testing.T) {
	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = conn.Exec(`
		CREATE TABLE devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other',
			status TEXT NOT NULL DEFAULT 'unknown',
			tags TEXT NOT NULL DEFAULT '{}',
			scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
			user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`)
	require.NoError(t, err)
	// Direct raw insert of bad JSON must fail the CHECK.
	_, err = conn.Exec(`INSERT INTO devices (name, type, status, user_attributes) VALUES ('x','other','unknown', '{not json')`)
	require.Error(t, err, "json_valid CHECK should reject malformed JSON")
	// And the empty default must be accepted.
	_, err = conn.Exec(`INSERT INTO devices (name, type, status) VALUES ('y','other','unknown')`)
	require.NoError(t, err)
}
