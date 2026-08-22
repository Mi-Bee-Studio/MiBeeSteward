// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package taskservice is the v2 CRUD bridge between scan_tasks DB rows and the
// v2 scheduler. It replaces the legacy scanner.ScanTaskService with identical
// API semantics (so the existing handler file needs no changes).
package taskservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"mibee-steward/internal/authz/scopeql"
	"mibee-steward/internal/cidrutil"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/metrics"
	"mibee-steward/internal/service/scannerv2/scheduler"
)

// Sentinel errors (preserved verbatim from v1 so handler error mapping still works).
var (
	ErrScanTaskNotFound      = errors.New("scan task not found")
	ErrScanNotRunning        = errors.New("scan is not running")
	ErrScanTaskDisabled      = errors.New("scan task is disabled")
	ErrSchedulerNotAvailable = errors.New("scheduler not available")
)

// ValidationError marks field-validation failures (bad targets / pipeline
// config) from Create/Update so the handler can map them to HTTP 400 with the
// underlying message instead of an opaque 500. The chain to the wrapped error
// (e.g. cidrutil.ErrReservedTarget) is preserved via Unwrap.
type ValidationError struct{ err error }

func (e *ValidationError) Error() string { return e.err.Error() }
func (e *ValidationError) Unwrap() error { return e.err }

// Service manages scan tasks: CRUD + trigger/cancel, keeping the DB and the
// scheduler in sync.
type Service struct {
	queries   *db.Queries
	conn      db.DBTX // raw connection for the network_id stamp + scope-restricted reads (nil = skip both)
	scheduler *scheduler.Scheduler
	// allowReservedTargets mirrors scanner.allow_reserved_targets (#317 escape
	// hatch for the loadgen synthetic plane); softens only the reserved-range
	// target check, never syntax.
	allowReservedTargets bool
}

// New constructs a Service. conn powers the scan_tasks.network_id stamping and
// the object-scope-restricted list paths (sqlc can't express a variable
// IN-list); it may be nil in unit tests that don't exercise those paths.
// scheduler may be nil (Trigger/Cancel return errors; CRUD still works for
// browsing).
func New(queries *db.Queries, conn db.DBTX, sched *scheduler.Scheduler, allowReservedTargets bool) *Service {
	return &Service{queries: queries, conn: conn, scheduler: sched, allowReservedTargets: allowReservedTargets}
}

// refreshTaskGauges recomputes mibee_scanner_tasks_total after a mutation
// (#238). Best-effort by design: a failed refresh is logged at debug and never
// fails the write it follows.
func (s *Service) refreshTaskGauges(ctx context.Context) {
	if err := metrics.RefreshScannerTaskGauges(ctx, s.queries); err != nil {
		slog.Debug("taskservice: refresh task gauges failed", "error", err)
	}
}

// ResolveNetworkFromTargets maps a scan task's targets to a networks row id
// (#138 Phase 2c). The targets resolve when they are a SINGLE CIDR whose
// normalized form matches one networks.cidr (the raw target string is tried
// too, covering non-canonical stored cidrs). Comma lists, IP ranges,
// hostnames, or no match → NULL — meaning cross-network/unresolved: visible
// to admins/open mode, hidden from restricted scopes. Best-effort by design;
// this is a visibility enforcement key, not an identity.
func ResolveNetworkFromTargets(ctx context.Context, conn db.DBTX, targets string) (sql.NullInt64, error) {
	fields := strings.FieldsFunc(targets, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	if len(fields) != 1 {
		return sql.NullInt64{}, nil
	}
	raw := strings.TrimSpace(fields[0])
	_, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return sql.NullInt64{}, nil // ranges / single IPs / hostnames → unscoped
	}
	for _, candidate := range []string{ipNet.String(), raw} {
		var id int64
		err := conn.QueryRowContext(ctx, `SELECT id FROM networks WHERE cidr = ? LIMIT 1`, candidate).Scan(&id)
		switch {
		case err == nil:
			return sql.NullInt64{Int64: id, Valid: true}, nil
		case errors.Is(err, sql.ErrNoRows):
			continue
		default:
			return sql.NullInt64{}, err
		}
	}
	return sql.NullInt64{}, nil
}

// stampTaskNetwork resolves a task's targets to a network and writes
// scan_tasks.network_id. Best-effort: resolution/DB failures are logged and
// leave the column NULL (unscoped), never failing the task write itself.
func (s *Service) stampTaskNetwork(ctx context.Context, taskID int64, targets string, logger *slog.Logger) {
	if s.conn == nil {
		return
	}
	netID, err := ResolveNetworkFromTargets(ctx, s.conn, targets)
	if err != nil {
		logger.Warn("scan task: network resolve failed; task left unscoped", "task_id", taskID, "error", err)
		return
	}
	if _, err := s.conn.ExecContext(ctx,
		`UPDATE scan_tasks SET network_id = ? WHERE id = ?`, netID, taskID); err != nil {
		logger.Warn("scan task: network stamp failed; task left unscoped", "task_id", taskID, "error", err)
	}
}

// taskNetworkInScope reports whether the task's network falls within scope. A
// global scope always passes; a restricted scope passes only when the task has
// a resolved network_id in the granted set (NULL = cross-network → hidden).
// A missing task returns false (callers map that to their not-found path).
func (s *Service) taskNetworkInScope(ctx context.Context, taskID int64, scope domain.Scope) bool {
	if scope.IsGlobal() {
		return true
	}
	if s.conn == nil {
		return true // scope disabled in this construction — fail open (tests)
	}
	var netID sql.NullInt64
	err := s.conn.QueryRowContext(ctx,
		`SELECT network_id FROM scan_tasks WHERE id = ?`, taskID).Scan(&netID)
	if err != nil {
		return false
	}
	return netID.Valid && scope.AllowsNetwork(netID.Int64)
}

// CreateTask inserts a task and registers its cron job.
func (s *Service) CreateTask(ctx context.Context, req domain.ScanTaskRequest) (domain.ScanTaskResponse, error) {
	// concurrent_hosts is optional on create: 0 means "not specified" and gets
	// the default (negative or >200 values still fail validation below). #246
	if req.ConcurrentHosts == 0 {
		req.ConcurrentHosts = domain.DefaultConcurrentHosts
	}
	if err := domain.ValidateScanTaskRequest(req, s.allowReservedTargets); err != nil {
		return domain.ScanTaskResponse{}, err
	}
	cfgJSON, err := json.Marshal(req.PipelineConfig)
	if err != nil {
		return domain.ScanTaskResponse{}, fmt.Errorf("marshal pipeline config: %w", err)
	}
	task, err := s.queries.CreateScanTask(ctx, db.CreateScanTaskParams{
		Name:            req.Name,
		Targets:         req.Targets,
		CronExpr:        req.CronExpr,
		PipelineConfig:  string(cfgJSON),
		GlobalLabels:    req.GlobalLabels,
		Timeout:         int64(req.Timeout),
		ConcurrentHosts: int64(req.ConcurrentHosts),
		CredentialID:    credentialIDPtr(req.CredentialID),
	})
	if err != nil {
		return domain.ScanTaskResponse{}, err
	}
	if s.scheduler != nil {
		if err := s.scheduler.AddJob(task.ID, task.CronExpr, task.Targets); err != nil {
			// Roll back the row we just inserted so we don't leave a task that
			// can never be triggered (its cron job failed to register).
			if _, delErr := s.queries.DeleteScanTask(ctx, task.ID); delErr != nil {
				return domain.ScanTaskResponse{}, fmt.Errorf("register cron job (and rollback failed: %v): %w", delErr, err)
			}
			return domain.ScanTaskResponse{}, fmt.Errorf("register cron job: %w", err)
		}
	}
	s.stampTaskNetwork(ctx, task.ID, task.Targets, slog.Default())
	s.refreshTaskGauges(ctx)
	return toTaskResponse(task), nil
}

// GetTask returns one task by ID. A restricted scope sees out-of-scope tasks
// as not found (they don't exist for that caller).
func (s *Service) GetTask(ctx context.Context, id int64, scope domain.Scope) (domain.ScanTaskResponse, error) {
	if !s.taskNetworkInScope(ctx, id, scope) {
		return domain.ScanTaskResponse{}, ErrScanTaskNotFound
	}
	task, err := s.queries.GetScanTask(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ScanTaskResponse{}, ErrScanTaskNotFound
		}
		return domain.ScanTaskResponse{}, err
	}
	return toTaskResponse(task), nil
}

// ListTasks returns a page of tasks + total count, optionally filtered by a
// case-insensitive substring search over name + targets. An empty search
// string disables the filter (matches the old behaviour) — both the list and
// the count use the same search term so pagination totals stay consistent.
// A restricted scope (#138 Phase 2c) sees only tasks whose network_id is in
// the granted set (NULL-network tasks are cross-network → hidden); the count
// mirrors the same WHERE.
func (s *Service) ListTasks(ctx context.Context, search string, limit, offset int, scope domain.Scope) ([]domain.ScanTaskResponse, int64, error) {
	if limit < 20 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	if !scope.IsGlobal() && s.conn != nil {
		return s.listTasksScoped(ctx, search, limit, offset, scope)
	}
	tasks, err := s.queries.ListScanTasksSearch(ctx, db.ListScanTasksSearchParams{
		Column1: search, // raw search term, used for the (? = '' OR ...) short-circuit
		LOWER:   search, // substring matched against lower(name)
		LOWER_2: search, // substring matched against lower(targets)
		Limit:   int64(limit),
		Offset:  int64(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.queries.CountScanTasksSearch(ctx, db.CountScanTasksSearchParams{
		Column1: search,
		LOWER:   search,
		LOWER_2: search,
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]domain.ScanTaskResponse, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, toTaskResponse(t))
	}
	return out, total, nil
}

// listTasksScoped mirrors ListScanTasksSearch/CountScanTasksSearch with the
// network-scope predicate ANDed in (sqlc can't express a variable IN-list).
// The SELECT column list MUST match db.ScanTask's field order for the Scan.
func (s *Service) listTasksScoped(ctx context.Context, search string, limit, offset int, scope domain.Scope) ([]domain.ScanTaskResponse, int64, error) {
	pred, predArgs := scopeql.NetworkPredicate(scope, "")

	where := "WHERE " + pred +
		" AND (? = '' OR INSTR(lower(name), lower(?)) > 0 OR INSTR(lower(targets), lower(?)) > 0)"

	var total int64
	countArgs := append(append([]any{}, predArgs...), search, search, search)
	if err := s.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scan_tasks `+where, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(append([]any{}, countArgs...), limit, offset)
	rows, err := s.conn.QueryContext(ctx, `SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
		FROM scan_tasks `+where+` ORDER BY id LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]domain.ScanTaskResponse, 0)
	for rows.Next() {
		var t db.ScanTask
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Targets, &t.CronExpr, &t.PipelineConfig, &t.GlobalLabels,
			&t.Timeout, &t.ConcurrentHosts, &t.CredentialID, &t.Enabled,
			&t.LastRunAt, &t.NextRunAt, &t.LastRunStatus, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		out = append(out, toTaskResponse(t))
	}
	return out, total, rows.Err()
}

// UpdateTask applies a partial update and re-registers the cron job if the
// schedule/targets changed.
func (s *Service) UpdateTask(ctx context.Context, id int64, req domain.UpdateScanTaskRequest) (domain.ScanTaskResponse, error) {
	existing, err := s.queries.GetScanTask(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ScanTaskResponse{}, ErrScanTaskNotFound
		}
		return domain.ScanTaskResponse{}, err
	}

	name := existing.Name
	if req.Name != nil {
		name = *req.Name
	}
	targets := existing.Targets
	if req.Targets != nil {
		targets = *req.Targets
		// The update path merges fields without re-running the full create
		// validation, so a reserved-range swap here would otherwise bypass
		// the #317 gate (create strict → update to 127.8.0.0/22).
		if err := cidrutil.ValidateTargetsFor(targets, s.allowReservedTargets); err != nil {
			return domain.ScanTaskResponse{}, &ValidationError{err: fmt.Errorf("targets: %w", err)}
		}
	}
	cron := existing.CronExpr
	if req.CronExpr != nil {
		cron = *req.CronExpr
	}
	globalLabels := existing.GlobalLabels
	if req.GlobalLabels != nil {
		globalLabels = *req.GlobalLabels
	}
	timeout := existing.Timeout
	if req.Timeout != nil {
		timeout = int64(*req.Timeout)
	}
	concurrent := existing.ConcurrentHosts
	if req.ConcurrentHosts != nil {
		concurrent = int64(*req.ConcurrentHosts)
	}
	// PipelineConfig is updated as a whole if provided.
	pipelineCfg := existing.PipelineConfig
	if req.PipelineConfig != nil {
		// Reject a config that disables every stage — it would produce a task
		// that finds nothing. This also guards against clients sending a
		// zero-valued PipelineConfig object (which serialises to all-disabled).
		if err := domain.ValidatePipelineConfig(*req.PipelineConfig); err != nil {
			return domain.ScanTaskResponse{}, &ValidationError{err: fmt.Errorf("pipeline_config: %w", err)}
		}
		b, err := json.Marshal(req.PipelineConfig)
		if err != nil {
			return domain.ScanTaskResponse{}, fmt.Errorf("marshal pipeline config: %w", err)
		}
		pipelineCfg = string(b)
	}

	// CredentialID: nil in the request = leave unchanged (preserve existing);
	// non-nil (incl. 0) = set/clear. We resolve this BEFORE the call so the
	// UPDATE always writes a concrete value (UpdateScanTask has no partial-PATCH
	// semantics — every field is rewritten).
	var credentialID *int64
	if req.CredentialID != nil {
		credentialID = req.CredentialID // explicit set (or clear via 0)
	} else {
		credentialID = existing.CredentialID // preserve
	}

	task, err := s.queries.UpdateScanTask(ctx, db.UpdateScanTaskParams{
		Name:            name,
		Targets:         targets,
		CronExpr:        cron,
		PipelineConfig:  pipelineCfg,
		GlobalLabels:    globalLabels,
		Timeout:         timeout,
		ConcurrentHosts: concurrent,
		CredentialID:    credentialID,
		ID:              id,
	})
	if err != nil {
		return domain.ScanTaskResponse{}, err
	}

	// Apply enabled toggle if requested. UpdateScanTask's generated SQL does not
	// touch `enabled` (by design — enabled has its own toggle query), so we apply
	// it separately via ToggleScanTaskEnabled and reflect it in the response.
	enabledChanged := false
	newEnabled := existing.Enabled
	if req.Enabled != nil {
		wantEnabled := int64(0)
		if *req.Enabled {
			wantEnabled = 1
		}
		if wantEnabled != existing.Enabled {
			if err := s.queries.ToggleScanTaskEnabled(ctx, db.ToggleScanTaskEnabledParams{
				Enabled: wantEnabled,
				ID:      id,
			}); err != nil {
				return domain.ScanTaskResponse{}, fmt.Errorf("toggle enabled: %w", err)
			}
			newEnabled = wantEnabled
			enabledChanged = true
		}
	}

	// Reconcile the scheduler job with the new state. The cron job must track:
	//   - schedule/targets changes (re-register), OR
	//   - enabled transitions (add on enable, remove on disable).
	cronChanged := cron != existing.CronExpr
	targetsChanged := targets != existing.Targets
	if s.scheduler != nil {
		switch {
		case newEnabled == 0:
			// Disabled: drop any registered job so it stops firing and triggers
			// return a clear "no job" error instead of silently doing nothing.
			s.scheduler.RemoveJob(id)
		case cronChanged || targetsChanged || (enabledChanged && newEnabled == 1):
			// Enabled (newly or persistently) with a changed schedule, or just
			// flipped back on: (re-)register the job.
			if err := s.scheduler.UpdateJob(id, cron, targets); err != nil {
				return domain.ScanTaskResponse{}, fmt.Errorf("re-register cron job: %w", err)
			}
		}
	}

	// toTaskResponse reads task.Enabled from the UpdateScanTask row, which does
	// not reflect the toggle we just applied — patch it so callers see the truth.
	resp := toTaskResponse(task)
	resp.Enabled = newEnabled == 1
	// Re-resolve the network key when the targets moved (#138 Phase 2c).
	if targetsChanged {
		s.stampTaskNetwork(ctx, id, targets, slog.Default())
	}
	s.refreshTaskGauges(ctx)
	return resp, nil
}

// DeleteTask removes the task and its cron job.
func (s *Service) DeleteTask(ctx context.Context, id int64) error {
	if _, err := s.queries.GetScanTask(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrScanTaskNotFound
		}
		return err
	}
	if s.scheduler != nil {
		s.scheduler.RemoveJob(id)
	}
	rows, err := s.queries.DeleteScanTask(ctx, id)
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrScanTaskNotFound
	}
	s.refreshTaskGauges(ctx)
	return nil
}

// TriggerTask fires the task's cron job asynchronously (fire-and-forget).
// Returns a synthetic "triggered" status; the real run row is created async.
//
// Errors are surfaced distinctly so callers (and the API handler) can map them
// to meaningful status codes: a disabled task is a client-side problem (409),
// while a missing scheduler/job is a server-side problem (500).
func (s *Service) TriggerTask(ctx context.Context, id int64) (domain.ScanRunResponse, error) {
	task, err := s.queries.GetScanTask(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ScanRunResponse{}, ErrScanTaskNotFound
		}
		return domain.ScanRunResponse{}, err
	}
	if task.Enabled == 0 {
		return domain.ScanRunResponse{}, ErrScanTaskDisabled
	}
	if s.scheduler == nil {
		return domain.ScanRunResponse{}, ErrSchedulerNotAvailable
	}
	if err := s.scheduler.TriggerNow(id); err != nil {
		// Distinguish "task has no registered cron job" (e.g. scheduler never
		// started, or job registration failed at create time) from other errors.
		return domain.ScanRunResponse{}, fmt.Errorf("trigger scan: %w", err)
	}
	return domain.ScanRunResponse{TaskID: id, Status: "triggered"}, nil
}

// CancelTask cancels an in-flight run and marks the latest run cancelled.
func (s *Service) CancelTask(ctx context.Context, id int64) error {
	if _, err := s.queries.GetScanTask(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrScanTaskNotFound
		}
		return err
	}
	if s.scheduler == nil {
		return ErrScanNotRunning
	}
	if err := s.scheduler.CancelTask(id); err != nil {
		return ErrScanNotRunning
	}
	if run, err := s.queries.GetLatestRun(ctx, id); err == nil && run.Status == "running" {
		// best-effort: mark the in-flight run cancelled so the UI does not
		// show "running" forever. Log on failure — without this the run row
		// stays stuck and the user cannot tell cancel didn't take effect.
		if uerr := s.queries.UpdateScanTaskRun(ctx, db.UpdateScanTaskRunParams{
			Status:       "cancelled",
			ErrorMessage: "cancelled by user",
			ID:           run.ID,
		}); uerr != nil {
			slog.Debug("taskservice: cancel run-status update failed", "task_id", id, "run_id", run.ID, "error", uerr)
		}
	}
	return nil
}

// GetTaskRuns returns run history for a task. A restricted scope sees runs of
// an out-of-scope task as not found (the sub-resources inherit the task's
// scope — single check here covers the whole list).
func (s *Service) GetTaskRuns(ctx context.Context, taskID, limit, offset int, scope domain.Scope) ([]domain.ScanRunResponse, int64, error) {
	if !s.taskNetworkInScope(ctx, int64(taskID), scope) {
		return nil, 0, ErrScanTaskNotFound
	}
	if limit < 20 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	runs, err := s.queries.ListScanTaskRuns(ctx, db.ListScanTaskRunsParams{
		Column1: int64(taskID), TaskID: int64(taskID), Limit: int64(limit), Offset: int64(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.queries.CountScanTaskRuns(ctx, db.CountScanTaskRunsParams{Column1: int64(taskID), TaskID: int64(taskID)})
	if err != nil {
		return nil, 0, err
	}
	out := make([]domain.ScanRunResponse, 0, len(runs))
	for _, r := range runs {
		out = append(out, toRunResponse(r))
	}
	return out, total, nil
}

// GetTaskResults returns per-host results for a task (scope semantics as
// GetTaskRuns).
func (s *Service) GetTaskResults(ctx context.Context, taskID, limit, offset int, scope domain.Scope) ([]domain.ScanResultResponse, int64, error) {
	if !s.taskNetworkInScope(ctx, int64(taskID), scope) {
		return nil, 0, ErrScanTaskNotFound
	}
	if limit < 20 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	results, err := s.queries.ListScanResults(ctx, db.ListScanResultsParams{
		Column1: int64(taskID), TaskID: int64(taskID), Column3: "", Ip: "", Column5: -1, Alive: 0, Limit: int64(limit), Offset: int64(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.queries.CountScanResults(ctx, db.CountScanResultsParams{Column1: int64(taskID), TaskID: int64(taskID), Column3: "", Ip: "", Column5: -1, Alive: 0})
	if err != nil {
		return nil, 0, err
	}
	out := make([]domain.ScanResultResponse, 0, len(results))
	for _, r := range results {
		out = append(out, toResultResponse(r))
	}
	return out, total, nil
}

func toTaskResponse(t db.ScanTask) domain.ScanTaskResponse {
	// pipeline_config is stored as a JSON string; decode it so the response
	// carries the object itself — the create REQUEST takes an object, and the
	// asymmetry forced every client to double-parse (#257). A malformed stored
	// value (hand-edited DB row) degrades to the zero config rather than
	// erroring the whole task listing.
	var pipeline domain.PipelineConfig
	if t.PipelineConfig != "" {
		_ = json.Unmarshal([]byte(t.PipelineConfig), &pipeline)
	}
	resp := domain.ScanTaskResponse{
		ID:              t.ID,
		Name:            t.Name,
		Targets:         t.Targets,
		CronExpr:        t.CronExpr,
		PipelineConfig:  pipeline,
		GlobalLabels:    t.GlobalLabels,
		Timeout:         int(t.Timeout),
		ConcurrentHosts: int(t.ConcurrentHosts),
		CredentialID:    t.CredentialID,
		Enabled:         t.Enabled == 1,
		LastRunAt:       t.LastRunAt,
		NextRunAt:       t.NextRunAt,
		CreatedAt:       t.CreatedAt,
		UpdatedAt:       t.UpdatedAt,
	}
	if t.LastRunStatus != nil {
		resp.LastRunStatus = *t.LastRunStatus
	}
	return resp
}

// credentialIDPtr converts the request's int64 credential_id to the nullable
// *int64 the DB layer expects. 0 → nil (no binding / use global default); any
// other value → pointer to that ID.
func credentialIDPtr(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

func toRunResponse(r db.ScanTaskRun) domain.ScanRunResponse {
	return domain.ScanRunResponse{
		ID:           r.ID,
		TaskID:       r.TaskID,
		Status:       r.Status,
		TotalHosts:   int(r.TotalHosts),
		AliveHosts:   int(r.AliveHosts),
		NewHosts:     int(r.NewHosts),
		UpdatedHosts: int(r.UpdatedHosts),
		DurationMs:   int(r.DurationMs),
		ErrorMessage: r.ErrorMessage,
		StartedAt:    r.StartedAt,
		FinishedAt:   r.FinishedAt,
		CreatedAt:    r.CreatedAt,
	}
}

func toResultResponse(r db.ScanResult) domain.ScanResultResponse {
	resp := domain.ScanResultResponse{
		ID:                   r.ID,
		TaskID:               r.TaskID,
		IP:                   r.Ip,
		Alive:                r.Alive == 1,
		RTTMs:                r.RttMs,
		Ports:                r.Ports,
		Services:             r.Services,
		SNMPData:             r.SnmpData,
		PrometheusDetected:   r.PrometheusDetected == 1,
		PrometheusURL:        r.PrometheusUrl,
		NodeExporterDetected: r.NodeExporterDetected == 1,
		NodeExporterURL:      r.NodeExporterUrl,
		NodeExporterData:     r.NodeExporterData,
		ScannedAt:            r.ScannedAt,
	}
	if r.RunID != nil {
		resp.RunID = *r.RunID
	}
	return resp
}
