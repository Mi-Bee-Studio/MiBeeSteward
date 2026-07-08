package service

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func setupDeviceService(t *testing.T) (*DeviceService, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS networks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			cidr TEXT, site TEXT, agent_id TEXT,
			metadata TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
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
			network_id INTEGER,
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	repo := repository.NewDeviceRepository(db)
	svc := NewDeviceService(repo, nil)
	return svc, db
}

func createTestDevice(t *testing.T, svc *DeviceService, name, ipAddr, deviceType string) *domain.DeviceResponse {
	t.Helper()
	resp, err := svc.Create(context.Background(), domain.CreateDeviceRequest{
		Name:      name,
		IPAddress: ipAddr,
		Type:      deviceType,
	})
	require.NoError(t, err)
	return resp
}

// 1. Create device with valid data
func TestDevice_Create_Success(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	resp, err := svc.Create(ctx, domain.CreateDeviceRequest{
		Name:        "Server-01",
		IPAddress:   "192.168.1.10",
		Type:        "pc",
		Brand:       "Dell",
		Model:       "R740",
		Location:    "Rack A",
		Description: "Main application server",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "Server-01", resp.Name)
	require.Equal(t, "192.168.1.10", resp.IPAddress)
	require.Equal(t, "pc", resp.Type)
	require.Equal(t, "Dell", resp.Brand)
	require.Equal(t, "unknown", resp.Status) // default status
	require.NotZero(t, resp.ID)
	require.False(t, resp.CreatedAt.IsZero())
}

// 2. Create with invalid IP
func TestDevice_Create_InvalidIP(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, domain.CreateDeviceRequest{
		Name:      "Bad-Device",
		IPAddress: "not-an-ip",
	})
	require.ErrorIs(t, err, ErrInvalidIP)
}

// 3. Create then get by ID
func TestDevice_Get_Success(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	created := createTestDevice(t, svc, "Sensor-01", "10.0.0.5", "iot")

	got, err := svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, got.ID)
	require.Equal(t, "Sensor-01", got.Name)
	require.Equal(t, "10.0.0.5", got.IPAddress)
	require.Equal(t, "iot", got.Type)
}

// 4. Get nonexistent ID → ErrDeviceNotFound
func TestDevice_Get_NotFound(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, 99999)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

// 5. List with pagination
func TestDevice_List_Pagination(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		createTestDevice(t, svc, "Device-"+string(rune('A'+i)), "10.0.0.1", "pc")
	}

	list, err := svc.List(ctx, domain.DeviceFilter{Limit: 2, Offset: 0})
	require.NoError(t, err)
	require.Len(t, list.Devices, 2)
	require.Equal(t, 5, list.Total)

	// Second page
	list2, err := svc.List(ctx, domain.DeviceFilter{Limit: 2, Offset: 2})
	require.NoError(t, err)
	require.Len(t, list2.Devices, 2)

	// Ensure pages differ
	require.NotEqual(t, list.Devices[0].ID, list2.Devices[0].ID)
}

// 6. Filter by type
func TestDevice_List_FilterByType(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	createTestDevice(t, svc, "PC-01", "10.0.0.1", "pc")
	createTestDevice(t, svc, "PC-02", "10.0.0.2", "pc")
	createTestDevice(t, svc, "IoT-01", "10.0.0.3", "iot")

	list, err := svc.List(ctx, domain.DeviceFilter{Type: "pc", Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Devices, 2)
	for _, d := range list.Devices {
		require.Equal(t, "pc", d.Type)
	}
	require.Equal(t, 2, list.Total)
}

// 7. Update device fields
func TestDevice_Update_Success(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	created := createTestDevice(t, svc, "Old-Name", "10.0.0.1", "pc")

	newName := "New-Name"
	newIP := "10.0.0.100"
	updated, err := svc.Update(ctx, created.ID, domain.UpdateDeviceRequest{
		Name:      &newName,
		IPAddress: &newIP,
	})
	require.NoError(t, err)
	require.Equal(t, "New-Name", updated.Name)
	require.Equal(t, "10.0.0.100", updated.IPAddress)

	// Original type unchanged
	require.Equal(t, "pc", updated.Type)
}

// 8. Delete device
func TestDevice_Delete_Success(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	created := createTestDevice(t, svc, "ToDelete", "10.0.0.1", "other")

	err := svc.Delete(ctx, created.ID)
	require.NoError(t, err)

	_, err = svc.Get(ctx, created.ID)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

// 9. Delete nonexistent → ErrDeviceNotFound
func TestDevice_Delete_NotFound(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	err := svc.Delete(ctx, 99999)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

// 10. GetStats — devices with different statuses and types
func TestDevice_GetStats(t *testing.T) {
	svc, db := setupDeviceService(t)
	ctx := context.Background()

	// Create 3 devices (default status=unknown)
	createTestDevice(t, svc, "Dev-A", "10.0.0.1", "pc")
	createTestDevice(t, svc, "Dev-B", "10.0.0.2", "iot")
	createTestDevice(t, svc, "Dev-C", "10.0.0.3", "embedded")

	// Manually flip one device to "online" to test status grouping
	_, err := db.Exec("UPDATE devices SET status = 'online' WHERE name = 'Dev-A'")
	require.NoError(t, err)
	_, err = db.Exec("UPDATE devices SET status = 'offline' WHERE name = 'Dev-B'")
	require.NoError(t, err)

	stats, err := svc.GetStats(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, stats)

	// Status counts
	require.Equal(t, int64(1), stats.ByStatus["online"])
	require.Equal(t, int64(1), stats.ByStatus["offline"])
	require.Equal(t, int64(1), stats.ByStatus["unknown"])

	// Type counts
	require.Equal(t, int64(1), stats.ByType["pc"])
	require.Equal(t, int64(1), stats.ByType["iot"])
	require.Equal(t, int64(1), stats.ByType["embedded"])
}

// 11. Update with invalid IP → ErrInvalidIP
func TestDevice_Update_InvalidIP(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	created := createTestDevice(t, svc, "Valid", "10.0.0.1", "pc")

	badIP := "999.999.999.999"
	_, err := svc.Update(ctx, created.ID, domain.UpdateDeviceRequest{
		IPAddress: &badIP,
	})
	require.ErrorIs(t, err, ErrInvalidIP)
}

// 12. Update nonexistent device → ErrDeviceNotFound
func TestDevice_Update_NotFound(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	name := "ghost"
	_, err := svc.Update(ctx, 99999, domain.UpdateDeviceRequest{
		Name: &name,
	})
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

// 13. Create with empty name → error
func TestDevice_Create_EmptyName(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, domain.CreateDeviceRequest{
		Name:      "",
		IPAddress: "10.0.0.1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "device name is required")
}

// 14. List defaults — limit clamp
func TestDevice_List_DefaultLimit(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	// Single device, query with limit=0 (should default to 20)
	createTestDevice(t, svc, "Solo", "10.0.0.1", "pc")

	list, err := svc.List(ctx, domain.DeviceFilter{Limit: 0})
	require.NoError(t, err)
	require.Len(t, list.Devices, 1)
}

// 15. Create with empty IP (allowed — no validation on empty string)
func TestDevice_Create_EmptyIP(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	resp, err := svc.Create(ctx, domain.CreateDeviceRequest{
		Name: "No-IP-Device",
	})
	require.NoError(t, err)
	require.Equal(t, "", resp.IPAddress)
}

// 16. Filter by status
func TestDevice_List_FilterByStatus(t *testing.T) {
	svc, db := setupDeviceService(t)
	ctx := context.Background()

	createTestDevice(t, svc, "Online-1", "10.0.0.1", "pc")
	createTestDevice(t, svc, "Unknown-1", "10.0.0.2", "pc")

	_, err := db.Exec("UPDATE devices SET status = 'online' WHERE name = 'Online-1'")
	require.NoError(t, err)

	list, err := svc.List(ctx, domain.DeviceFilter{Status: "online", Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Devices, 1)
	require.Equal(t, "Online-1", list.Devices[0].Name)
	require.Equal(t, 1, list.Total)
}

// 17. Total reflects actual count, not page size
func TestDevice_List_TotalIsRealCount(t *testing.T) {
	svc, _ := setupDeviceService(t)
	ctx := context.Background()

	// Create 7 devices
	for i := 0; i < 7; i++ {
		createTestDevice(t, svc, fmt.Sprintf("Total-Dev-%d", i), fmt.Sprintf("10.0.%d.1", i), "pc")
	}

	// Request page with limit=2
	list, err := svc.List(ctx, domain.DeviceFilter{Limit: 2, Offset: 0})
	require.NoError(t, err)
	require.Len(t, list.Devices, 2) // page has 2 items
	require.Equal(t, 7, list.Total) // but total is 7

	// Second page also has correct total
	list2, err := svc.List(ctx, domain.DeviceFilter{Limit: 2, Offset: 2})
	require.NoError(t, err)
	require.Len(t, list2.Devices, 2)
	require.Equal(t, 7, list2.Total)
}
