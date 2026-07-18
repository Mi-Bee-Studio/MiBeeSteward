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

// CreateConfig creates a new dashboard configuration.
func (s *DashboardService) CreateConfig(ctx context.Context, params db.CreateDashboardConfigParams) (db.DashboardConfig, error) {
	return s.queries.CreateDashboardConfig(ctx, params)
}

// UpdateConfig updates an existing dashboard configuration.
func (s *DashboardService) UpdateConfig(ctx context.Context, params db.UpdateDashboardConfigParams) (db.DashboardConfig, error) {
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
func (s *DashboardService) Overview(ctx context.Context) (*domain.DashboardOverviewResponse, error) {
	out := &domain.DashboardOverviewResponse{Generated: time.Now()}

	// --- 1. Device totals + by_status (reuse the existing GROUP BY queries) ---
	statusRows, err := s.queries.CountByStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("overview: count by status: %w", err)
	}
	dev := domain.OverviewDevices{
		ByType:     map[string]int64{},
		ByLocation: map[string]int64{},
	}
	for _, r := range statusRows {
		dev.Total += r.Count
		switch r.Status {
		case "online":
			dev.Online = r.Count
		case "offline":
			dev.Offline = r.Count
		case "unknown":
			dev.Unknown = r.Count
		}
	}
	if dev.Total > 0 {
		dev.OnlineRate = float64(dev.Online) / float64(dev.Total)
	}

	// --- 2. by_type (full population, not a 200-row sample) ---
	typeRows, err := s.queries.CountDevicesByType(ctx)
	if err != nil {
		return nil, fmt.Errorf("overview: count by type: %w", err)
	}
	for _, r := range typeRows {
		key := r.Type
		if key == "" {
			key = "unknown"
		}
		dev.ByType[key] = r.Count
	}

	// --- 3. by_location (raw GROUP BY — no sqlc query exists for it) ---
	locRows, err := s.dbConn.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(location,''),'unknown') AS loc, COUNT(*) FROM devices GROUP BY loc`)
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

	// --- 4. Recent scan tasks + runs + run-status distribution ---
	scan, err := s.overviewScanning(ctx)
	if err != nil {
		return nil, err
	}
	out.Scanning = scan

	// --- 5. Abnormal device list (offline, most-recently-scanned first) ---
	offline, err := s.dbConn.QueryContext(ctx, `
		SELECT id, name, ip_address, type, status, last_scanned_at
		FROM devices WHERE status='offline'
		ORDER BY COALESCE(last_scanned_at, '1970-01-01') DESC, id DESC
		LIMIT 10`)
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
// counts.
func (s *DashboardService) overviewScanning(ctx context.Context) (domain.OverviewScanning, error) {
	out := domain.OverviewScanning{RunsByStatus: map[string]int64{}}

	tasksTotal, err := s.queries.CountScanTasks(ctx)
	if err != nil {
		return out, fmt.Errorf("overview: count tasks: %w", err)
	}
	out.TasksTotal = tasksTotal

	runsTotal, err := s.queries.CountScanTaskRuns(ctx, db.CountScanTaskRunsParams{Column1: 0, TaskID: 0})
	if err != nil {
		return out, fmt.Errorf("overview: count runs: %w", err)
	}
	out.RunsTotal = runsTotal

	// Recent tasks (last 5 by id desc).
	tasks, err := s.queries.ListScanTasks(ctx, db.ListScanTasksParams{Limit: 5, Offset: 0})
	if err != nil {
		return out, fmt.Errorf("overview: list tasks: %w", err)
	}
	out.RecentTasks = make([]domain.OverviewScanTask, 0, len(tasks))
	for _, t := range tasks {
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

	// Recent runs across all tasks (task_id=0 ⇒ no filter), last 5.
	runs, err := s.queries.ListScanTaskRuns(ctx, db.ListScanTaskRunsParams{
		Column1: 0, TaskID: 0, Limit: 5, Offset: 0,
	})
	if err != nil {
		return out, fmt.Errorf("overview: list runs: %w", err)
	}
	out.RecentRuns = make([]domain.OverviewScanRun, 0, len(runs))
	for _, r := range runs {
		out.RecentRuns = append(out.RecentRuns, runToOverview(r))
		// tally status distribution across ALL runs (not just recent) — cheap to
		// derive from the recent slice would be wrong, so we do a separate query.
	}

	// Run-status distribution across all runs (raw, one GROUP BY).
	distRows, err := s.dbConn.QueryContext(ctx, `SELECT status, COUNT(*) FROM scan_task_runs GROUP BY status`)
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

	// Most recent completed run (the latest "discovery" result).
	completed, err := s.dbConn.QueryContext(ctx, `
		SELECT id, task_id, status, total_hosts, alive_hosts, new_hosts, duration_ms, error_message, started_at, finished_at
		FROM scan_task_runs WHERE status='completed'
		ORDER BY COALESCE(finished_at, started_at, created_at) DESC LIMIT 1`)
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
