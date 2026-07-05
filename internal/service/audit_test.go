package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"

	_ "modernc.org/sqlite"
)

// setupAuditTest creates an in-memory SQLite DB with the audit_logs table
// and returns an AuditService ready for testing.
func setupAuditTest(t *testing.T) (*AuditService, *sql.DB, *db.Queries) {
	t.Helper()

	dbConn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })

	// Create audit_logs table
	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			details TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// Create indexes
	_, err = dbConn.Exec(`
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	`)
	require.NoError(t, err)

	svc := NewAuditService(dbConn)
	queries := db.New(dbConn)
	return svc, dbConn, queries
}

// insertAuditLog inserts a single audit log entry via raw SQL.
func insertAuditLog(t *testing.T, dbConn *sql.DB, userID *int64, action, resourceType, resourceID string, createdAt time.Time) {
	t.Helper()
	_, err := dbConn.Exec(
		`INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, action, resourceType, resourceID, "127.0.0.1", "test-agent", "{}", createdAt,
	)
	require.NoError(t, err)
}

// 1. List all audit logs with no filters
func TestAudit_ListAll(t *testing.T) {
	svc, dbConn, _ := setupAuditTest(t)
	ctx := context.Background()

	now := time.Now()
	userID := int64(1)
	insertAuditLog(t, dbConn, &userID, "user.login", "auth", "1", now)
	insertAuditLog(t, dbConn, &userID, "device.create", "device", "10", now.Add(-time.Hour))
	insertAuditLog(t, dbConn, nil, "auth.failed", "auth", "", now.Add(-2*time.Hour))

	resp, err := svc.List(ctx, domain.AuditLogFilter{
		Limit:  100,
		Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 3)
	require.Equal(t, 3, resp.Total)
}

// 2. Filter by action
func TestAudit_FilterByAction(t *testing.T) {
	svc, dbConn, _ := setupAuditTest(t)
	ctx := context.Background()

	now := time.Now()
	uid := int64(1)
	insertAuditLog(t, dbConn, &uid, "user.login", "auth", "1", now)
	insertAuditLog(t, dbConn, &uid, "device.create", "device", "10", now.Add(-time.Hour))
	insertAuditLog(t, dbConn, &uid, "device.delete", "device", "20", now.Add(-2*time.Hour))

	action := "device.create"
	resp, err := svc.List(ctx, domain.AuditLogFilter{
		Action: &action,
		Limit:  100,
		Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 1)
	require.Equal(t, 1, resp.Total)
	require.Equal(t, "device.create", resp.AuditLogs[0].Action)
}

// 3. Filter by user_id
func TestAudit_FilterByUserID(t *testing.T) {
	svc, dbConn, _ := setupAuditTest(t)
	ctx := context.Background()

	now := time.Now()
	uid1 := int64(1)
	uid2 := int64(2)
	insertAuditLog(t, dbConn, &uid1, "user.login", "auth", "1", now)
	insertAuditLog(t, dbConn, &uid2, "user.login", "auth", "2", now)
	insertAuditLog(t, dbConn, &uid1, "device.create", "device", "10", now.Add(-time.Hour))

	resp, err := svc.List(ctx, domain.AuditLogFilter{
		UserID: &uid1,
		Limit:  100,
		Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 2)
	require.Equal(t, 2, resp.Total)
	for _, log := range resp.AuditLogs {
		require.NotNil(t, log.UserID)
		require.Equal(t, int64(1), *log.UserID)
	}
}

// 4. Filter by resource_type
func TestAudit_FilterByResourceType(t *testing.T) {
	svc, dbConn, _ := setupAuditTest(t)
	ctx := context.Background()

	now := time.Now()
	uid := int64(1)
	insertAuditLog(t, dbConn, &uid, "device.create", "device", "10", now)
	insertAuditLog(t, dbConn, &uid, "user.login", "auth", "1", now.Add(-time.Hour))
	insertAuditLog(t, dbConn, &uid, "device.delete", "device", "20", now.Add(-2*time.Hour))

	rt := "auth"
	resp, err := svc.List(ctx, domain.AuditLogFilter{
		ResourceType: &rt,
		Limit:        100,
		Offset:       0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 1)
	require.Equal(t, 1, resp.Total)
	require.Equal(t, "auth", resp.AuditLogs[0].ResourceType)
}

// 5. Filter by date range
func TestAudit_FilterByDateRange(t *testing.T) {
	svc, dbConn, _ := setupAuditTest(t)
	ctx := context.Background()

	now := time.Now()
	uid := int64(1)
	insertAuditLog(t, dbConn, &uid, "old.event", "test", "1", now.Add(-48*time.Hour))
	insertAuditLog(t, dbConn, &uid, "recent.event", "test", "2", now.Add(-2*time.Hour))
	insertAuditLog(t, dbConn, &uid, "current.event", "test", "3", now)

	from := now.Add(-24 * time.Hour)
	resp, err := svc.List(ctx, domain.AuditLogFilter{
		DateFrom: &from,
		Limit:    100,
		Offset:   0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 2, "should include recent and current, exclude old")
	require.Equal(t, 2, resp.Total)

	to := now.Add(-1 * time.Hour)
	resp, err = svc.List(ctx, domain.AuditLogFilter{
		DateTo: &to,
		Limit:  100,
		Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 2, "should include old and recent, exclude current")
	require.Equal(t, 2, resp.Total)
}

// 6. Pagination
func TestAudit_Pagination(t *testing.T) {
	svc, dbConn, _ := setupAuditTest(t)
	ctx := context.Background()

	now := time.Now()
	uid := int64(1)
	for i := 0; i < 10; i++ {
		insertAuditLog(t, dbConn, &uid, "test.event", "test", "1", now.Add(-time.Duration(i)*time.Hour))
	}

	// Page 1: limit 3
	resp, err := svc.List(ctx, domain.AuditLogFilter{
		Limit:  3,
		Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 3)
	require.Equal(t, 10, resp.Total)

	// Page 2: offset 3, limit 3
	resp, err = svc.List(ctx, domain.AuditLogFilter{
		Limit:  3,
		Offset: 3,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 3)
	require.Equal(t, 10, resp.Total)

	// Last page: offset 9, should get 1
	resp, err = svc.List(ctx, domain.AuditLogFilter{
		Limit:  3,
		Offset: 9,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 1)
	require.Equal(t, 10, resp.Total)
}

// 7. Empty result when no matches
func TestAudit_EmptyResult(t *testing.T) {
	svc, _, _ := setupAuditTest(t)
	ctx := context.Background()

	action := "nonexistent"
	resp, err := svc.List(ctx, domain.AuditLogFilter{
		Action: &action,
		Limit:  100,
		Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, resp.AuditLogs, 0)
	require.Equal(t, 0, resp.Total)
}
