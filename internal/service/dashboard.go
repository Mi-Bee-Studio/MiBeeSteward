// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"mibee-steward/internal/authz/scopeql"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// DashboardService handles dashboard config CRUD and Prometheus/VM query proxying.
type DashboardService struct {
	queries        *db.Queries
	dbConn         db.DBTX // raw connection for the Overview aggregations (GROUP BY location, offline list)
	prometheusURL  string
	dataSourceType string
	client         *http.Client
}

// NewDashboardService creates a new DashboardService.
func NewDashboardService(dbConn db.DBTX, cfg *config.Config) *DashboardService {
	return &DashboardService{
		queries:        db.New(dbConn),
		dbConn:         dbConn,
		prometheusURL:  cfg.Dashboard.PrometheusURL,
		dataSourceType: cfg.Dashboard.DataSourceType,
		client:         &http.Client{Timeout: 30 * time.Second},
	}
}

// dataSourceEndpoint returns the appropriate URL based on the configured data source type.
func (s *DashboardService) dataSourceEndpoint() (string, error) {
	switch s.dataSourceType {
	case "prometheus":
		if s.prometheusURL == "" {
			return "", fmt.Errorf("prometheus URL not configured")
		}
		return s.prometheusURL, nil
	default:
		if s.prometheusURL == "" {
			return "", fmt.Errorf("prometheus URL not configured")
		}
		return s.prometheusURL, nil
	}
}

// ListConfigs returns all dashboard configurations.
func (s *DashboardService) ListConfigs(ctx context.Context) ([]db.DashboardConfig, error) {
	return s.queries.ListConfigs(ctx)
}

// CreateConfig creates a new dashboard configuration. Position <= 0 means
// "not specified" and lands after all existing widgets (max+1), so clients
// never need to compute display order (#247).
func (s *DashboardService) CreateConfig(ctx context.Context, params db.CreateDashboardConfigParams) (db.DashboardConfig, error) {
	if params.Position <= 0 {
		maxPos, err := s.queries.GetMaxDashboardConfigPosition(ctx)
		if err != nil {
			return db.DashboardConfig{}, fmt.Errorf("resolve widget position: %w", err)
		}
		params.Position = maxPos + 1
	}
	return s.queries.CreateDashboardConfig(ctx, params)
}

// UpdateConfig updates an existing dashboard configuration. This is a
// full-replace PUT; position <= 0 falls back to max+1 (a client that omits
// position loses its slot ordering rather than storing an invalid 0).
func (s *DashboardService) UpdateConfig(ctx context.Context, params db.UpdateDashboardConfigParams) (db.DashboardConfig, error) {
	if params.Position <= 0 {
		maxPos, err := s.queries.GetMaxDashboardConfigPosition(ctx)
		if err != nil {
			return db.DashboardConfig{}, fmt.Errorf("resolve widget position: %w", err)
		}
		params.Position = maxPos + 1
	}
	return s.queries.UpdateDashboardConfig(ctx, params)
}

// DeleteConfig deletes a dashboard configuration by ID.
func (s *DashboardService) DeleteConfig(ctx context.Context, id int64) error {
	affected, err := s.queries.DeleteDashboardConfig(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("dashboard config not found")
	}
	return nil
}

// Query performs an instant query against the configured Prometheus/VM data source.
func (s *DashboardService) Query(ctx context.Context, query string, ts string) ([]byte, error) {
	baseURL, err := s.dataSourceEndpoint()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/query?query=%s", baseURL, query)
	if ts != "" {
		url += "&time=" + ts
	}

	return s.proxyRequest(ctx, url)
}

// QueryRange performs a range query against the configured Prometheus/VM data source.
func (s *DashboardService) QueryRange(ctx context.Context, query, start, end, step string) ([]byte, error) {
	baseURL, err := s.dataSourceEndpoint()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/query_range?query=%s&start=%s&end=%s&step=%s",
		baseURL, query, start, end, step)

	return s.proxyRequest(ctx, url)
}

// proxyRequest executes an HTTP GET against the data source and returns the raw response body.
func (s *DashboardService) proxyRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &UpstreamError{Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// UpstreamError indicates the Prometheus/VM data source is unreachable.
type UpstreamError struct {
	Err error
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("data source unreachable: %v", e.Err)
}

// Overview returns the aggregated dashboard payload computed server-side over
// the full dataset: device status/type/location distributions, recent scan
// activity, and the offline-device list. The default dashboard front-end
// consumes this single call instead of pulling /devices?limit=200 and computing
// pie charts in the browser (which capped at 200 rows and skewed the picture).
//
// scope (#138 Phase 2b): the device aggregates (status/type/location/offline)
// honor object-level network scope — a closed-mode non-admin caller sees counts
// only for their granted networks. The scanning section (recent tasks/runs) is
// cross-network discovery metadata and is intentionally NOT scoped (it has no
// per-network association until scan_tasks.network_id lands).
func (s *DashboardService) Overview(ctx context.Context, scope domain.Scope) (*domain.DashboardOverviewResponse, error) {
	out := &domain.DashboardOverviewResponse{Generated: time.Now()}
	// pred is "1=1" for a global scope (no filtering) — so the same raw query
	// serves both the admin/open path and the closed-mode restricted path.
	pred, predArgs := scopeql.NetworkPredicate(scope, "")

	dev := domain.OverviewDevices{
		ByType:     map[string]int64{},
		ByLocation: map[string]int64{},
	}

	// --- 1. Device totals + by_status ---
	statusRows, err := s.dbConn.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM devices WHERE `+pred+` GROUP BY status`, predArgs...)
	if err != nil {
		return nil, fmt.Errorf("overview: count by status: %w", err)
	}
	for statusRows.Next() {
		var status string
		var c int64
		if err := statusRows.Scan(&status, &c); err != nil {
			statusRows.Close()
			return nil, fmt.Errorf("overview: scan status: %w", err)
		}
		dev.Total += c
		switch status {
		case "online":
			dev.Online = c
		case "offline":
			dev.Offline = c
		case "unknown":
			dev.Unknown = c
		}
	}
	statusRows.Close()
	if err := statusRows.Err(); err != nil {
		return nil, fmt.Errorf("overview: status rows: %w", err)
	}
	if dev.Total > 0 {
		dev.OnlineRate = float64(dev.Online) / float64(dev.Total)
	}

	// --- 2. by_type (full population, not a 200-row sample) ---
	typeRows, err := s.dbConn.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(type,''),'unknown'), COUNT(*) FROM devices WHERE `+pred+` GROUP BY type`, predArgs...)
	if err != nil {
		return nil, fmt.Errorf("overview: count by type: %w", err)
	}
	for typeRows.Next() {
		var t string
		var c int64
		if err := typeRows.Scan(&t, &c); err != nil {
			typeRows.Close()
			return nil, fmt.Errorf("overview: scan type: %w", err)
		}
		dev.ByType[t] = c
	}
	typeRows.Close()
	if err := typeRows.Err(); err != nil {
		return nil, fmt.Errorf("overview: type rows: %w", err)
	}

	// --- 3. by_location (raw GROUP BY — no sqlc query exists for it) ---
	locRows, err := s.dbConn.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(location,''),'unknown') AS loc, COUNT(*) FROM devices WHERE `+pred+` GROUP BY loc`, predArgs...)
	if err != nil {
		return nil, fmt.Errorf("overview: count by location: %w", err)
	}
	for locRows.Next() {
		var loc string
		var c int64
		if err := locRows.Scan(&loc, &c); err != nil {
			locRows.Close()
			return nil, fmt.Errorf("overview: scan location: %w", err)
		}
		dev.ByLocation[loc] = c
	}
	locRows.Close()
	if err := locRows.Err(); err != nil {
		return nil, fmt.Errorf("overview: location rows: %w", err)
	}
	out.Devices = dev

	// --- 4. Recent scan tasks + runs + run-status distribution (cross-network; NOT scoped) ---
	scan, err := s.overviewScanning(ctx, scope)
	if err != nil {
		return nil, err
	}
	out.Scanning = scan

	// --- 5. Abnormal device list (offline, most-recently-scanned first) ---
	offlineArgs := append(append([]any{}, predArgs...), 10)
	offline, err := s.dbConn.QueryContext(ctx, `
		SELECT id, name, ip_address, type, status, last_scanned_at
		FROM devices WHERE status='offline' AND `+pred+`
		ORDER BY COALESCE(last_scanned_at, '1970-01-01') DESC, id DESC
		LIMIT ?`, offlineArgs...)
	if err != nil {
		return nil, fmt.Errorf("overview: list offline: %w", err)
	}
	for offline.Next() {
		var d domain.OverviewDevice
		if err := offline.Scan(&d.ID, &d.Name, &d.IPAddress, &d.Type, &d.Status, &d.LastScannedAt); err != nil {
			offline.Close()
			return nil, fmt.Errorf("overview: scan offline row: %w", err)
		}
		out.Abnormal = append(out.Abnormal, d)
	}
	offline.Close()
	if err := offline.Err(); err != nil {
		return nil, fmt.Errorf("overview: offline rows: %w", err)
	}

	return out, nil
}

// overviewScanning gathers recent scan tasks/runs and the run-status
// distribution so the dashboard reflects discovery activity, not just device
// counts. scope (#138 Phase 2c) restricts every aggregate to tasks whose
// network_id is in the granted set — runs scope through their task.
func (s *DashboardService) overviewScanning(ctx context.Context, scope domain.Scope) (domain.OverviewScanning, error) {
	out := domain.OverviewScanning{RunsByStatus: map[string]int64{}}

	// taskPred scopes the scan_tasks table; runJoin scopes run aggregates
	// through the task. Both are no-ops ("1=1") for a global scope.
	taskPred, taskArgs := scopeql.NetworkPredicate(scope, "")
	runJoin := `FROM scan_task_runs r JOIN scan_tasks t ON r.task_id = t.id WHERE ` + taskPred
	runArgs := taskArgs

	if err := s.dbConn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scan_tasks WHERE `+taskPred, taskArgs...).Scan(&out.TasksTotal); err != nil {
		return out, fmt.Errorf("overview: count tasks: %w", err)
	}

	if err := s.dbConn.QueryRowContext(ctx,
		`SELECT COUNT(*) `+runJoin, runArgs...).Scan(&out.RunsTotal); err != nil {
		return out, fmt.Errorf("overview: count runs: %w", err)
	}

	// Recent tasks (last 5 by id desc). Initialized to empty (not nil) so the
	// JSON keeps rendering [] on an empty DB (matches the previous sqlc path).
	out.RecentTasks = make([]domain.OverviewScanTask, 0)
	taskRows, err := s.dbConn.QueryContext(ctx, `SELECT id, name, targets, enabled, last_run_at, last_run_status
		FROM scan_tasks WHERE `+taskPred+` ORDER BY id DESC LIMIT 5`, taskArgs...)
	if err != nil {
		return out, fmt.Errorf("overview: list tasks: %w", err)
	}
	for taskRows.Next() {
		var t struct {
			ID            int64
			Name          string
			Targets       string
			Enabled       int64
			LastRunAt     *time.Time
			LastRunStatus *string
		}
		if err := taskRows.Scan(&t.ID, &t.Name, &t.Targets, &t.Enabled, &t.LastRunAt, &t.LastRunStatus); err != nil {
			taskRows.Close()
			return out, fmt.Errorf("overview: scan task row: %w", err)
		}
		ot := domain.OverviewScanTask{
			ID:        t.ID,
			Name:      t.Name,
			Targets:   t.Targets,
			Enabled:   t.Enabled != 0,
			LastRunAt: t.LastRunAt,
		}
		if t.LastRunStatus != nil {
			ot.LastRunStatus = *t.LastRunStatus
		}
		out.RecentTasks = append(out.RecentTasks, ot)
	}
	taskRows.Close()
	if err := taskRows.Err(); err != nil {
		return out, fmt.Errorf("overview: task rows: %w", err)
	}

	// Recent runs across all visible tasks, last 5 (scoped through the task).
	out.RecentRuns = make([]domain.OverviewScanRun, 0)
	runRows, err := s.dbConn.QueryContext(ctx, `SELECT r.id, r.task_id, r.status, r.total_hosts, r.alive_hosts, r.new_hosts, r.updated_hosts,
		r.duration_ms, r.error_message, r.started_at, r.finished_at, r.created_at
		`+runJoin+` ORDER BY r.id DESC LIMIT 5`, runArgs...)
	if err != nil {
		return out, fmt.Errorf("overview: list runs: %w", err)
	}
	for runRows.Next() {
		var r db.ScanTaskRun
		if err := runRows.Scan(&r.ID, &r.TaskID, &r.Status, &r.TotalHosts, &r.AliveHosts,
			&r.NewHosts, &r.UpdatedHosts, &r.DurationMs, &r.ErrorMessage,
			&r.StartedAt, &r.FinishedAt, &r.CreatedAt); err != nil {
			runRows.Close()
			return out, fmt.Errorf("overview: scan run row: %w", err)
		}
		out.RecentRuns = append(out.RecentRuns, runToOverview(r))
	}
	runRows.Close()
	if err := runRows.Err(); err != nil {
		return out, fmt.Errorf("overview: run rows: %w", err)
	}

	// Run-status distribution across all visible runs (raw, one GROUP BY).
	distRows, err := s.dbConn.QueryContext(ctx,
		`SELECT r.status, COUNT(*) `+runJoin+` GROUP BY r.status`, runArgs...)
	if err != nil {
		return out, fmt.Errorf("overview: runs by status: %w", err)
	}
	for distRows.Next() {
		var st string
		var c int64
		if err := distRows.Scan(&st, &c); err != nil {
			distRows.Close()
			return out, fmt.Errorf("overview: scan run-status row: %w", err)
		}
		out.RunsByStatus[st] = c
	}
	distRows.Close()
	if err := distRows.Err(); err != nil {
		return out, fmt.Errorf("overview: run-status rows: %w", err)
	}

	// Most recent completed visible run (the latest "discovery" result).
	completed, err := s.dbConn.QueryContext(ctx, `
		SELECT r.id, r.task_id, r.status, r.total_hosts, r.alive_hosts, r.new_hosts, r.duration_ms, r.error_message, r.started_at, r.finished_at
		`+runJoin+` AND r.status='completed'
		ORDER BY COALESCE(r.finished_at, r.started_at, r.created_at) DESC LIMIT 1`, runArgs...)
	if err != nil {
		return out, fmt.Errorf("overview: last discovery: %w", err)
	}
	for completed.Next() {
		var r db.ScanTaskRun
		if err := completed.Scan(&r.ID, &r.TaskID, &r.Status, &r.TotalHosts, &r.AliveHosts,
			&r.NewHosts, &r.DurationMs, &r.ErrorMessage, &r.StartedAt, &r.FinishedAt); err != nil {
			completed.Close()
			return out, fmt.Errorf("overview: scan last-discovery row: %w", err)
		}
		ov := runToOverview(r)
		out.LastDiscovery = &ov
	}
	completed.Close()
	if err := completed.Err(); err != nil {
		return out, fmt.Errorf("overview: last-discovery rows: %w", err)
	}

	return out, nil
}

// runToOverview maps a sqlc ScanTaskRun into the dashboard's lighter projection.
func runToOverview(r db.ScanTaskRun) domain.OverviewScanRun {
	return domain.OverviewScanRun{
		ID:           r.ID,
		TaskID:       r.TaskID,
		Status:       r.Status,
		TotalHosts:   r.TotalHosts,
		AliveHosts:   r.AliveHosts,
		NewHosts:     r.NewHosts,
		DurationMs:   r.DurationMs,
		ErrorMessage: r.ErrorMessage,
		StartedAt:    r.StartedAt,
		FinishedAt:   r.FinishedAt,
	}
}
