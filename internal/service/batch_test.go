package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/repository"
)

// setupBatchTestDB creates an in-memory SQLite DB with schema for batch tests.
func setupBatchTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	_, err = d.ExecContext(context.Background(), batchSchemaSQL)
	require.NoError(t, err)

	return d
}

// batchSchemaSQL contains a minimal schema for batch operation tests.
const batchSchemaSQL = `
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    password_changed_at TIMESTAMP,
    must_change_password BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`

// batchInsertDevices inserts test devices and returns their IDs.
func batchInsertDevices(t *testing.T, d *sql.DB, count int) []int64 {
	t.Helper()
	ids := make([]int64, 0, count)
	for i := 0; i < count; i++ {
		res, err := d.ExecContext(context.Background(),
			"INSERT INTO devices (name, type, status) VALUES (?, ?, ?)",
			"Device"+string(rune('0'+i)), "other", "unknown",
		)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		ids = append(ids, id)
	}
	return ids
}

// batchInsertUsers inserts test users and returns their IDs.
func batchInsertUsers(t *testing.T, d *sql.DB, count int) []int64 {
	t.Helper()
	ids := make([]int64, 0, count)
	for i := 0; i < count; i++ {
		res, err := d.ExecContext(context.Background(),
			"INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
			"user"+string(rune('0'+i)), "user"+string(rune('0'+i))+"@test.com", "hash",
		)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		ids = append(ids, id)
	}
	return ids
}

func TestBatchService_DeleteDevices_EmptyIDs(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)

	deleted, err := svc.DeleteDevices(context.Background(), nil, 1)
	assert.Equal(t, int64(0), deleted)
	assert.ErrorIs(t, err, ErrBatchEmptyIDs)
}

func TestBatchService_DeleteDevices_Single(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertDevices(t, d, 1)

	deleted, err := svc.DeleteDevices(ctx, ids, 99)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	// Verify device is gone
	var count int
	err = d.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id = ?", ids[0]).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestBatchService_DeleteDevices_Multiple(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertDevices(t, d, 5)

	deleted, err := svc.DeleteDevices(ctx, ids, 99)
	require.NoError(t, err)
	assert.Equal(t, int64(5), deleted)

	// Verify all gone
	var count int
	err = d.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestBatchService_DeleteDevices_NonexistentIDs(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)

	deleted, err := svc.DeleteDevices(context.Background(), []int64{9999, 10000}, 99)
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

func TestBatchService_DeleteDevices_Mixed(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertDevices(t, d, 2)

	// Mix real IDs with non-existent ones
	mixed := []int64{ids[0], 9999, ids[1]}
	deleted, err := svc.DeleteDevices(ctx, mixed, 99)
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)
}

func TestBatchService_DeleteDevices_AuditLog(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertDevices(t, d, 2)

	_, err := svc.DeleteDevices(ctx, ids, 42)
	require.NoError(t, err)

	var action string
	var details string
	err = d.QueryRowContext(ctx, "SELECT action, details FROM audit_logs WHERE user_id = 42 AND action = 'admin.device.batch_delete'").Scan(&action, &details)
	require.NoError(t, err)
	assert.Equal(t, "admin.device.batch_delete", action)
	assert.Contains(t, details, "deleted 2 devices")
}

func TestBatchService_UpdateDeviceStatuses_EmptyIDs(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)

	updated, err := svc.UpdateDeviceStatuses(context.Background(), nil, "online", 1)
	assert.Equal(t, int64(0), updated)
	assert.ErrorIs(t, err, ErrBatchEmptyIDs)
}

func TestBatchService_UpdateDeviceStatuses_InvalidStatus(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)

	updated, err := svc.UpdateDeviceStatuses(context.Background(), []int64{1}, "invalid", 1)
	assert.Equal(t, int64(0), updated)
	assert.ErrorIs(t, err, ErrBatchInvalidStatus)
}

func TestBatchService_UpdateDeviceStatuses_Success(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertDevices(t, d, 3)

	updated, err := svc.UpdateDeviceStatuses(ctx, ids, "online", 99)
	require.NoError(t, err)
	assert.Equal(t, int64(3), updated)

	// Verify status
	for _, id := range ids {
		var status string
		err = d.QueryRowContext(ctx, "SELECT status FROM devices WHERE id = ?", id).Scan(&status)
		require.NoError(t, err)
		assert.Equal(t, "online", status)
	}
}

func TestBatchService_UpdateDeviceStatuses_AllValidStatuses(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	for _, status := range []string{"online", "offline", "unknown"} {
		ids := batchInsertDevices(t, d, 1)
		updated, err := svc.UpdateDeviceStatuses(ctx, ids, status, 99)
		require.NoError(t, err)
		assert.Equal(t, int64(1), updated)

		var s string
		d.QueryRowContext(ctx, "SELECT status FROM devices WHERE id = ?", ids[0]).Scan(&s)
		assert.Equal(t, status, s)
	}
}

func TestBatchService_UpdateDeviceStatuses_AuditLog(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertDevices(t, d, 2)

	_, err := svc.UpdateDeviceStatuses(ctx, ids, "offline", 42)
	require.NoError(t, err)

	var action string
	err = d.QueryRowContext(ctx, "SELECT action FROM audit_logs WHERE user_id = 42 AND action = 'admin.device.batch_update_status'").Scan(&action)
	require.NoError(t, err)
	assert.Equal(t, "admin.device.batch_update_status", action)
}

func TestBatchService_DeleteUsers_EmptyIDs(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)

	deleted, err := svc.DeleteUsers(context.Background(), nil, 1)
	assert.Equal(t, int64(0), deleted)
	assert.ErrorIs(t, err, ErrBatchEmptyIDs)
}

func TestBatchService_DeleteUsers_SelfDelete(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)

	deleted, err := svc.DeleteUsers(context.Background(), []int64{1, 2, 1}, 1)
	assert.Equal(t, int64(0), deleted)
	assert.ErrorIs(t, err, ErrBatchSelfDelete)
}

func TestBatchService_DeleteUsers_Success(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertUsers(t, d, 3)
	currentUser := int64(99) // Not in the delete list

	deleted, err := svc.DeleteUsers(ctx, ids, currentUser)
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted)

	// Verify all gone
	var count int
	err = d.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestBatchService_DeleteUsers_AuditLog(t *testing.T) {
	d := setupBatchTestDB(t)
	defer d.Close()

	auditRepo := repository.NewAuditRepository(d)
	svc := NewBatchService(d, auditRepo)
	ctx := context.Background()

	ids := batchInsertUsers(t, d, 2)

	_, err := svc.DeleteUsers(ctx, ids, 42)
	require.NoError(t, err)

	var action string
	err = d.QueryRowContext(ctx, "SELECT action FROM audit_logs WHERE user_id = 42 AND action = 'admin.user.batch_delete'").Scan(&action)
	require.NoError(t, err)
	assert.Equal(t, "admin.user.batch_delete", action)
}

func TestIsValidDeviceStatus(t *testing.T) {
	tests := []struct {
		status  string
		isValid bool
	}{
		{"online", true},
		{"offline", true},
		{"unknown", true},
		{"invalid", false},
		{"", false},
		{"ONLINE", false},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			assert.Equal(t, tt.isValid, isValidDeviceStatus(tt.status))
		})
	}
}

// Verify error types are properly defined for use in handlers.
func TestBatchErrors(t *testing.T) {
	assert.True(t, errors.Is(ErrBatchEmptyIDs, ErrBatchEmptyIDs))
	assert.True(t, errors.Is(ErrBatchSelfDelete, ErrBatchSelfDelete))
	assert.True(t, errors.Is(ErrBatchInvalidStatus, ErrBatchInvalidStatus))
	assert.False(t, errors.Is(ErrBatchEmptyIDs, ErrBatchSelfDelete))
}
