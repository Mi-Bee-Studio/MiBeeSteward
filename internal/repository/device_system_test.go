package repository

import (
	"context"
	"database/sql"
	"testing"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// setupDeviceSystemTestDB creates an in-memory SQLite database with devices and device_systems tables,
// inserts a test device, and returns the DB + device ID + repository.
func setupDeviceSystemTestDB(t *testing.T) (*DeviceSystemRepository, *sql.DB, int64) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Create devices table (required for FK constraint)
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

	// Insert a test device for FK constraint
	var deviceID int64
	err = db.QueryRowContext(context.Background(),
		"INSERT INTO devices (name, type, ip_address) VALUES (?, ?, ?) RETURNING id",
		"Test-Device", "pc", "10.0.0.1",
	).Scan(&deviceID)
	require.NoError(t, err)

	repo := NewDeviceSystemRepository(db)
	return repo, db, deviceID
}

// helper: create a test system and return its ID
func createTestSystem(t *testing.T, repo *DeviceSystemRepository, deviceID int64, name string) int64 {
	t.Helper()
	ctx := context.Background()
	sys, err := repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:     name,
		Category: "web_app",
	})
	require.NoError(t, err)
	return sys.ID
}

// ---------- Tests ----------

func TestDeviceSystemRepository_Create(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	sys, err := repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:           "WebApp-01",
		EntryURL:       "http://localhost:8080",
		Description:    "Main web application",
		Category:       "web_app",
		MetricsURL:     "http://localhost:8080/metrics",
		MetricsEnabled: true,
		Tags:           `{"env":"prod"}`,
	})

	require.NoError(t, err)
	require.NotZero(t, sys.ID)
	require.Equal(t, deviceID, sys.DeviceID)
	require.Equal(t, "WebApp-01", sys.Name)
	require.Equal(t, "http://localhost:8080", sys.EntryUrl)
	require.Equal(t, "Main web application", sys.Description)
	require.Equal(t, "web_app", sys.Category)
	require.Equal(t, "http://localhost:8080/metrics", sys.MetricsUrl)
	require.Equal(t, int64(1), sys.MetricsEnabled)
	require.Equal(t, `{"env":"prod"}`, sys.Tags)
	require.False(t, sys.CreatedAt.IsZero())
	require.False(t, sys.UpdatedAt.IsZero())
}

func TestDeviceSystemRepository_Create_Defaults(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	sys, err := repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name: "MinimalSystem",
	})

	require.NoError(t, err)
	require.Equal(t, "custom", sys.Category) // default category
	require.Equal(t, "{}", sys.Tags)         // default tags
	require.Equal(t, int64(0), sys.MetricsEnabled)
	require.Equal(t, "", sys.EntryUrl)
	require.Equal(t, "", sys.MetricsUrl)
}

func TestDeviceSystemRepository_GetByID(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	created, err := repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:     "GetMe",
		Category: "database",
	})
	require.NoError(t, err)

	got, err := repo.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, got.ID)
	require.Equal(t, "GetMe", got.Name)
	require.Equal(t, deviceID, got.DeviceID)
	require.Equal(t, "database", got.Category)
}

func TestDeviceSystemRepository_GetByID_NotFound(t *testing.T) {
	repo, _, _ := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	_, err := repo.GetByID(ctx, 99999)
	require.Error(t, err)
}

func TestDeviceSystemRepository_ListByDevice(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	// Create 3 systems for the same device
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-A", Category: "web_app"})
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-B", Category: "database"})
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-C", Category: "middleware"})

	systems, err := repo.ListByDevice(ctx, deviceID, domain.DeviceSystemFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, systems, 3)
}

func TestDeviceSystemRepository_ListByDevice_WithCategoryFilter(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-A", Category: "web_app"})
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-B", Category: "database"})
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-C", Category: "web_app"})

	systems, err := repo.ListByDevice(ctx, deviceID, domain.DeviceSystemFilter{
		Category: "web_app",
		Limit:    10,
	})
	require.NoError(t, err)
	require.Len(t, systems, 2)
	for _, s := range systems {
		require.Equal(t, "web_app", s.Category)
	}
}

func TestDeviceSystemRepository_ListByDevice_Pagination(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-1"})
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-2"})
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-3"})

	// Page 1
	page1, err := repo.ListByDevice(ctx, deviceID, domain.DeviceSystemFilter{Limit: 2, Offset: 0})
	require.NoError(t, err)
	require.Len(t, page1, 2)

	// Page 2
	page2, err := repo.ListByDevice(ctx, deviceID, domain.DeviceSystemFilter{Limit: 2, Offset: 2})
	require.NoError(t, err)
	require.Len(t, page2, 1)

	// Pages must differ
	require.NotEqual(t, page1[0].ID, page2[0].ID)
}

func TestDeviceSystemRepository_Update(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	created, err := repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:        "OldName",
		Description: "Old description",
		Category:    "custom",
	})
	require.NoError(t, err)

	updated, err := repo.Update(ctx, db.UpdateDeviceSystemParams{
		ID:             created.ID,
		DeviceID:       created.DeviceID,
		Name:           "NewName",
		EntryUrl:       created.EntryUrl,
		Description:    "New description",
		Category:       "web_app",
		MetricsUrl:     created.MetricsUrl,
		MetricsEnabled: created.MetricsEnabled,
		Tags:           created.Tags,
	})
	require.NoError(t, err)
	require.Equal(t, "NewName", updated.Name)
	require.Equal(t, "New description", updated.Description)
	require.Equal(t, "web_app", updated.Category)
	require.Equal(t, created.ID, updated.ID)
}

func TestDeviceSystemRepository_Delete(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	sysID := createTestSystem(t, repo, deviceID, "ToDelete")

	err := repo.Delete(ctx, sysID)
	require.NoError(t, err)

	// Verify deleted
	_, err = repo.GetByID(ctx, sysID)
	require.Error(t, err)
}

func TestDeviceSystemRepository_Delete_NotFound(t *testing.T) {
	repo, _, _ := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	err := repo.Delete(ctx, 99999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "device system not found")
}

func TestDeviceSystemRepository_CountByDevice(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	count, err := repo.CountByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Equal(t, int64(0), count)

	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-1"})
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{Name: "Sys-2"})

	count, err = repo.CountByDevice(ctx, deviceID)
	require.NoError(t, err)
	require.Equal(t, int64(2), count)
}

func TestDeviceSystemRepository_ListForSD(t *testing.T) {
	repo, _, deviceID := setupDeviceSystemTestDB(t)
	ctx := context.Background()

	// Create system with metrics enabled
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:           "Monitored",
		MetricsEnabled: true,
		MetricsURL:     "http://localhost:9090/metrics",
	})

	// Create system with metrics disabled
	repo.Create(ctx, deviceID, domain.CreateDeviceSystemRequest{
		Name:           "Unmonitored",
		MetricsEnabled: false,
	})

	rows, err := repo.ListForSD(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1) // only metrics_enabled=1
	require.Equal(t, "Monitored", rows[0].Name)
	require.Equal(t, "Test-Device", rows[0].DeviceName)
	require.Equal(t, "pc", rows[0].DeviceType)
}
