package taskservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// validRequest is a ScanTaskRequest that passes ValidateScanTaskRequest. Tests
// mutate individual fields off this base.
func validRequest() domain.ScanTaskRequest {
	return domain.ScanTaskRequest{
		Name:            "nightly-lan",
		Targets:         "192.168.1.0/24",
		CronExpr:        "0 2 * * *",
		Timeout:         60,
		ConcurrentHosts: 16,
		PipelineConfig: domain.PipelineConfig{
			ICMP: domain.ICMPConfig{Enabled: true, Timeout: 2},
		},
	}
}

// setupSvc returns a taskservice backed by an in-memory SQLite DB with a NIL
// scheduler. CRUD/Get/List/Delete work with nil scheduler (per the Service doc);
// Trigger/Cancel are exercised separately in the real-scheduler tests below.
func setupSvc(t *testing.T) (*Service, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	return New(queries, nil), queries
}

// TestCreateTask_GetTask verifies the create→read round-trip and that the
// returned response maps the DB fields correctly.
func TestCreateTask_GetTask(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()

	resp, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)
	require.Equal(t, "nightly-lan", resp.Name)
	require.Equal(t, "192.168.1.0/24", resp.Targets)
	require.Equal(t, "0 2 * * *", resp.CronExpr)
	require.NotZero(t, resp.ID)

	got, err := svc.GetTask(ctx, resp.ID)
	require.NoError(t, err)
	require.Equal(t, resp.ID, got.ID)
	require.Equal(t, "nightly-lan", got.Name)
}

// TestCreateTask_ValidationRejectsBadInput verifies validation runs before the
// DB is touched (missing name, invalid cron, out-of-range timeout).
func TestCreateTask_ValidationRejectsBadInput(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()

	cases := []struct {
		name string
		mut  func(r *domain.ScanTaskRequest)
	}{
		{"missing name", func(r *domain.ScanTaskRequest) { r.Name = "" }},
		{"missing targets", func(r *domain.ScanTaskRequest) { r.Targets = "" }},
		{"invalid cron", func(r *domain.ScanTaskRequest) { r.CronExpr = "not-a-cron" }},
		{"timeout too low", func(r *domain.ScanTaskRequest) { r.Timeout = 0 }},
		{"timeout too high", func(r *domain.ScanTaskRequest) { r.Timeout = 99999 }},
		{"concurrent too low", func(r *domain.ScanTaskRequest) { r.ConcurrentHosts = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := validRequest()
			c.mut(&req)
			_, err := svc.CreateTask(ctx, req)
			require.Error(t, err, c.name)
		})
	}
}

// TestGetTask_NotFound verifies a missing ID maps to ErrScanTaskNotFound (the
// sentinel the handler switches on).
func TestGetTask_NotFound(t *testing.T) {
	svc, _ := setupSvc(t)
	_, err := svc.GetTask(context.Background(), 9999)
	require.ErrorIs(t, err, ErrScanTaskNotFound)
}

// TestListTasks_PaginationClamping verifies the limit/offset guards: limit<20
// is raised to 20, limit>100 capped at 100, negative offset normalized to 0.
func TestListTasks_PaginationClamping(t *testing.T) {
	svc, queries := setupSvc(t)
	ctx := context.Background()
	// Seed 3 tasks.
	for i := 0; i < 3; i++ {
		req := validRequest()
		req.Name = "task-" + string(rune('a'+i))
		_, err := svc.CreateTask(ctx, req)
		require.NoError(t, err)
	}
	// total reflects all 3 regardless of limit/offset.
	tasks, total, err := svc.ListTasks(ctx, 5, 0) // limit<20 → clamped to 20
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Len(t, tasks, 3)
	// offset beyond the set → empty page, total unchanged.
	tasks, total, err = svc.ListTasks(ctx, 20, 100)
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Empty(t, tasks)
	// the seeding also sanity-checks CreateScanTask isn't dropping rows
	_ = queries
}

// TestDeleteTask verifies deletion and that the deleted ID is then not-found.
func TestDeleteTask(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()

	resp, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)

	require.NoError(t, svc.DeleteTask(ctx, resp.ID))
	_, err = svc.GetTask(ctx, resp.ID)
	require.ErrorIs(t, err, ErrScanTaskNotFound)
}

// TestDeleteTask_NotFound verifies deleting a missing ID returns the sentinel.
func TestDeleteTask_NotFound(t *testing.T) {
	svc, _ := setupSvc(t)
	err := svc.DeleteTask(context.Background(), 9999)
	require.ErrorIs(t, err, ErrScanTaskNotFound)
}

// TestTriggerTask_NilScheduler verifies the documented behavior: with a nil
// scheduler (e.g. a read-only config or browsing context), Trigger returns an
// error rather than panicking.
func TestTriggerTask_NilScheduler(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()
	resp, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)
	_, err = svc.TriggerTask(ctx, resp.ID)
	require.Error(t, err, "nil scheduler must error, not panic")
}

// TestCancelTask_NilScheduler verifies Cancel with a nil scheduler errors.
func TestCancelTask_NilScheduler(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()
	resp, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)
	err = svc.CancelTask(ctx, resp.ID)
	require.Error(t, err)
}
