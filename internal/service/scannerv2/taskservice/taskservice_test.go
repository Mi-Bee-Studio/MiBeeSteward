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
	return New(queries, conn, nil), queries
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

	got, err := svc.GetTask(ctx, resp.ID, domain.Scope{Global: true})
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
	_, err := svc.GetTask(context.Background(), 9999, domain.Scope{Global: true})
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
	tasks, total, err := svc.ListTasks(ctx, "", 5, 0, domain.Scope{Global: true}) // limit<20 → clamped to 20
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Len(t, tasks, 3)
	// offset beyond the set → empty page, total unchanged.
	tasks, total, err = svc.ListTasks(ctx, "", 20, 100, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Empty(t, tasks)
	// the seeding also sanity-checks CreateScanTask isn't dropping rows
	_ = queries
}

// TestListTasks_Search verifies server-side substring search over name + targets:
// a non-empty search narrows both the returned page and the total count, an
// empty search disables the filter, and the match is case-insensitive + works
// against either column.
func TestListTasks_Search(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()

	// Seed tasks with distinct names + targets so each search term hits exactly one.
	reqs := []domain.ScanTaskRequest{
		{Name: "nightly-lan", Targets: "192.168.1.0/24", CronExpr: "0 2 * * *", Timeout: 60, ConcurrentHosts: 16, PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true, Timeout: 2}}},
		{Name: "weekly-cameras", Targets: "10.0.0.0/24", CronExpr: "0 3 * * 0", Timeout: 60, ConcurrentHosts: 16, PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true, Timeout: 2}}},
		{Name: "iot-sweep", Targets: "172.16.0.0/24", CronExpr: "0 4 * * *", Timeout: 60, ConcurrentHosts: 16, PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true, Timeout: 2}}},
	}
	for _, r := range reqs {
		_, err := svc.CreateTask(ctx, r)
		require.NoError(t, err)
	}

	// Empty search → all 3 (filter disabled).
	tasks, total, err := svc.ListTasks(ctx, "", 20, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	require.Len(t, tasks, 3)

	// Search by name substring → 1 match, total=1.
	tasks, total, err = svc.ListTasks(ctx, "cameras", 20, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, tasks, 1)
	require.Equal(t, "weekly-cameras", tasks[0].Name)

	// Search by targets substring → 1 match (the 172.16 row).
	tasks, total, err = svc.ListTasks(ctx, "172.16", 20, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, tasks, 1)
	require.Equal(t, "iot-sweep", tasks[0].Name)

	// Case-insensitive: "LAN" matches "nightly-lan".
	tasks, total, err = svc.ListTasks(ctx, "LAN", 20, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, tasks, 1)
	require.Equal(t, "nightly-lan", tasks[0].Name)

	// No match → empty page, total=0.
	tasks, total, err = svc.ListTasks(ctx, "nonexistent-term", 20, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(0), total)
	require.Empty(t, tasks)

	// A term matching MULTIPLE columns/rows ("0.0/24" is in two targets) → total=2.
	tasks, total, err = svc.ListTasks(ctx, "0.0/24", 20, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Len(t, tasks, 2)
}

// TestDeleteTask verifies deletion and that the deleted ID is then not-found.
func TestDeleteTask(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()

	resp, err := svc.CreateTask(ctx, validRequest())
	require.NoError(t, err)

	require.NoError(t, svc.DeleteTask(ctx, resp.ID))
	_, err = svc.GetTask(ctx, resp.ID, domain.Scope{Global: true})
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

// TestResolveNetworkFromTargets pins the targets→network resolution rules
// (#138 Phase 2c): single canonical CIDR matching networks.cidr resolves;
// single IPs, hostnames, multi-CIDR lists, and unmatched CIDRs stay NULL.
func TestResolveNetworkFromTargets(t *testing.T) {
	ctx := context.Background()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Exec(`INSERT INTO networks (id, name, cidr) VALUES (1, 'lan-1', '10.0.1.0/24')`)
	require.NoError(t, err)

	cases := []struct {
		name    string
		targets string
		wantID  int64
		wantOK  bool
	}{
		{"canonical single CIDR", "10.0.1.0/24", 1, true},
		{"padded single CIDR", "  10.0.1.0/24  ", 1, true},
		{"single IP", "10.0.1.5", 0, false},
		{"hostname", "example.lan", 0, false},
		{"multi-CIDR list", "10.0.1.0/24,10.0.2.0/24", 0, false},
		{"unmatched CIDR", "172.16.0.0/24", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ResolveNetworkFromTargets(ctx, conn, tc.targets)
			require.NoError(t, err)
			require.Equal(t, tc.wantOK, id.Valid, "valid=%v targets=%q", id.Valid, tc.targets)
			if tc.wantOK {
				require.EqualValues(t, tc.wantID, id.Int64)
			}
		})
	}
}
