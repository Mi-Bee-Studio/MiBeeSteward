package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func setupDeviceSystemService(t *testing.T) (*DeviceSystemService, *sql.DB, int64) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Create devices table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other' CHECK(type IN ('pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas')),
			brand TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			purpose TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('online', 'offline', 'unknown')),
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
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// Create device_systems table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS device_systems (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			entry_url TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			category TEXT NOT NULL DEFAULT 'custom' CHECK(category IN ('web_app', 'database', 'middleware', 'custom')),
			metrics_url TEXT NOT NULL DEFAULT '',
			metrics_enabled INTEGER NOT NULL DEFAULT 0,
			tags TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_device_systems_device ON device_systems(device_id);
		CREATE INDEX IF NOT EXISTS idx_device_systems_category ON device_systems(category);
		CREATE INDEX IF NOT EXISTS idx_device_systems_metrics_enabled ON device_systems(metrics_enabled);
	`)
	require.NoError(t, err)

	// Insert a test device
	var deviceID int64
	err = db.QueryRowContext(context.Background(),
		"INSERT INTO devices (name, type, ip_address) VALUES (?, ?, ?) RETURNING id",
		"Test-Device", "pc", "10.0.0.1",
	).Scan(&deviceID)
	require.NoError(t, err)

	repo := repository.NewDeviceSystemRepository(db)
	svc := NewDeviceSystemService(repo)
	return svc, db, deviceID
}

// helper: create a valid system for reuse in tests
func createTestDeviceSystem(t *testing.T, svc *DeviceSystemService, deviceID int64, name string) *domain.DeviceSystemResponse {
	t.Helper()
	resp, err := svc.Create(context.Background(), deviceID, domain.CreateDeviceSystemRequest{
		Name:     name,
		Category: "web_app",
	})
	require.NoError(t, err)
	return resp
}

// ---------- Create ----------

func TestDeviceSystemService_Create_Valid(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	resp, err := svc.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:           "TestSystem",
		EntryURL:       "http://localhost:8080",
		Description:    "A test system",
		Category:       "web_app",
		MetricsURL:     "http://localhost:8080/metrics",
		MetricsEnabled: true,
		Tags:           `{"env":"test"}`,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "TestSystem", resp.Name)
	require.Equal(t, "http://localhost:8080", resp.EntryURL)
	require.Equal(t, "A test system", resp.Description)
	require.Equal(t, "web_app", resp.Category)
	require.Equal(t, "http://localhost:8080/metrics", resp.MetricsURL)
	require.Equal(t, true, resp.MetricsEnabled)
	require.Equal(t, `{"env":"test"}`, resp.Tags)
	require.NotZero(t, resp.ID)
	require.Equal(t, deviceID, resp.DeviceID)
	require.False(t, resp.CreatedAt.IsZero())
}

func TestDeviceSystemService_Create_EmptyName(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name: "",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "system name is required")
}

func TestDeviceSystemService_Create_InvalidEntryURL(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:     "BadURL",
		EntryURL: "not-a-url",
	})
	require.True(t, errors.Is(err, ErrInvalidEntryURL), "expected ErrInvalidEntryURL, got: %v", err)
}

func TestDeviceSystemService_Create_InvalidMetricsURL(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:       "BadMetrics",
		MetricsURL: "ftp://bad-scheme.com",
	})
	require.True(t, errors.Is(err, ErrInvalidMetricsURL), "expected ErrInvalidMetricsURL, got: %v", err)
}

func TestDeviceSystemService_Create_URLNoScheme(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:     "NoScheme",
		EntryURL: "localhost:8080",
	})
	require.True(t, errors.Is(err, ErrInvalidEntryURL), "expected ErrInvalidEntryURL for URL without scheme, got: %v", err)
}

// ---------- Get ----------

func TestDeviceSystemService_Get_Found(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	created := createTestDeviceSystem(t, svc, deviceID, "FindMe")

	got, err := svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, got.ID)
	require.Equal(t, "FindMe", got.Name)
	require.Equal(t, deviceID, got.DeviceID)
}

func TestDeviceSystemService_Get_NotFound(t *testing.T) {
	svc, _, _ := setupDeviceSystemService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, 99999)
	require.True(t, errors.Is(err, ErrDeviceSystemNotFound), "expected ErrDeviceSystemNotFound, got: %v", err)
}

// ---------- List ----------

func TestDeviceSystemService_ListByDevice(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	createTestDeviceSystem(t, svc, deviceID, "Sys-A")
	createTestDeviceSystem(t, svc, deviceID, "Sys-B")
	createTestDeviceSystem(t, svc, deviceID, "Sys-C")

	list, err := svc.ListByDevice(ctx, deviceID, domain.DeviceSystemFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Systems, 3)
	require.Equal(t, 3, list.Total)
}

func TestDeviceSystemService_ListByDevice_DefaultPagination(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	createTestDeviceSystem(t, svc, deviceID, "OnlyOne")

	// Limit=0 should default to 20
	list, err := svc.ListByDevice(ctx, deviceID, domain.DeviceSystemFilter{})
	require.NoError(t, err)
	require.Len(t, list.Systems, 1)
	require.Equal(t, 1, list.Total)
}

// ---------- Update ----------

func TestDeviceSystemService_Update_Partial(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	created := createTestDeviceSystem(t, svc, deviceID, "Original")

	newName := "Updated"
	newDesc := "Updated description"
	updated, err := svc.Update(ctx, created.ID, domain.UpdateDeviceSystemRequest{
		Name:        &newName,
		Description: &newDesc,
	})

	require.NoError(t, err)
	require.Equal(t, "Updated", updated.Name)
	require.Equal(t, "Updated description", updated.Description)
	require.Equal(t, created.EntryURL, updated.EntryURL) // unchanged
	require.Equal(t, created.Category, updated.Category) // unchanged
	require.Equal(t, created.ID, updated.ID)
}

func TestDeviceSystemService_Update_NotFound(t *testing.T) {
	svc, _, _ := setupDeviceSystemService(t)
	ctx := context.Background()

	name := "ghost"
	_, err := svc.Update(ctx, 99999, domain.UpdateDeviceSystemRequest{
		Name: &name,
	})
	require.True(t, errors.Is(err, ErrDeviceSystemNotFound), "expected ErrDeviceSystemNotFound, got: %v", err)
}

func TestDeviceSystemService_Update_InvalidURL(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	created := createTestDeviceSystem(t, svc, deviceID, "ValidSystem")

	badURL := "not-valid"
	_, err := svc.Update(ctx, created.ID, domain.UpdateDeviceSystemRequest{
		EntryURL: &badURL,
	})
	require.True(t, errors.Is(err, ErrInvalidEntryURL), "expected ErrInvalidEntryURL, got: %v", err)
}

func TestDeviceSystemService_Update_MetricsEnabledToggle(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	created := createTestDeviceSystem(t, svc, deviceID, "MetricsTest")
	require.Equal(t, false, created.MetricsEnabled) // default false

	enabled := true
	updated, err := svc.Update(ctx, created.ID, domain.UpdateDeviceSystemRequest{
		MetricsEnabled: &enabled,
	})
	require.NoError(t, err)
	require.Equal(t, true, updated.MetricsEnabled)
}

// ---------- Delete ----------

func TestDeviceSystemService_Delete(t *testing.T) {
	svc, _, deviceID := setupDeviceSystemService(t)
	ctx := context.Background()

	created := createTestDeviceSystem(t, svc, deviceID, "DeleteMe")

	err := svc.Delete(ctx, created.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = svc.Get(ctx, created.ID)
	require.True(t, errors.Is(err, ErrDeviceSystemNotFound))
}

func TestDeviceSystemService_Delete_NotFound(t *testing.T) {
	svc, _, _ := setupDeviceSystemService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, 99999)
	require.True(t, errors.Is(err, ErrDeviceSystemNotFound), "expected ErrDeviceSystemNotFound, got: %v", err)
}
