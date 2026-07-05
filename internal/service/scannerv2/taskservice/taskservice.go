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

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2/scheduler"
)

// Sentinel errors (preserved verbatim from v1 so handler error mapping still works).
var (
	ErrScanTaskNotFound = errors.New("scan task not found")
	ErrScanNotRunning   = errors.New("scan is not running")
	ErrScanTaskDisabled = errors.New("scan task is disabled")
)

// Service manages scan tasks: CRUD + trigger/cancel, keeping the DB and the
// scheduler in sync.
type Service struct {
	queries   *db.Queries
	scheduler *scheduler.Scheduler
}

// New constructs a Service. scheduler may be nil (Trigger/Cancel return errors;
// CRUD still works for browsing).
func New(queries *db.Queries, sched *scheduler.Scheduler) *Service {
	return &Service{queries: queries, scheduler: sched}
}

// CreateTask inserts a task and registers its cron job.
func (s *Service) CreateTask(ctx context.Context, req domain.ScanTaskRequest) (domain.ScanTaskResponse, error) {
	if err := domain.ValidateScanTaskRequest(req); err != nil {
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
	return toTaskResponse(task), nil
}

// GetTask returns one task by ID.
func (s *Service) GetTask(ctx context.Context, id int64) (domain.ScanTaskResponse, error) {
	task, err := s.queries.GetScanTask(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ScanTaskResponse{}, ErrScanTaskNotFound
		}
		return domain.ScanTaskResponse{}, err
	}
	return toTaskResponse(task), nil
}

// ListTasks returns a page of tasks + total count.
func (s *Service) ListTasks(ctx context.Context, limit, offset int) ([]domain.ScanTaskResponse, int64, error) {
	if limit < 20 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	tasks, err := s.queries.ListScanTasks(ctx, db.ListScanTasksParams{Limit: int64(limit), Offset: int64(offset)})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.queries.CountScanTasks(ctx)
	if err != nil {
		return nil, 0, err
	}
	out := make([]domain.ScanTaskResponse, 0, len(tasks))
	for _, t := range tasks {
		out = append(out, toTaskResponse(t))
	}
	return out, total, nil
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
			return domain.ScanTaskResponse{}, fmt.Errorf("pipeline_config: %w", err)
		}
		b, err := json.Marshal(req.PipelineConfig)
		if err != nil {
			return domain.ScanTaskResponse{}, fmt.Errorf("marshal pipeline config: %w", err)
		}
		pipelineCfg = string(b)
	}

	task, err := s.queries.UpdateScanTask(ctx, db.UpdateScanTaskParams{
		Name:            name,
		Targets:         targets,
		CronExpr:        cron,
		PipelineConfig:  pipelineCfg,
		GlobalLabels:    globalLabels,
		Timeout:         timeout,
		ConcurrentHosts: concurrent,
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
		return domain.ScanRunResponse{}, errors.New("scheduler not available")
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
		_ = s.queries.UpdateScanTaskRun(ctx, db.UpdateScanTaskRunParams{
			Status:       "cancelled",
			ErrorMessage: "cancelled by user",
			ID:           run.ID,
		})
	}
	return nil
}

// GetTaskRuns returns run history for a task.
func (s *Service) GetTaskRuns(ctx context.Context, taskID, limit, offset int) ([]domain.ScanRunResponse, int64, error) {
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

// GetTaskResults returns per-host results for a task.
func (s *Service) GetTaskResults(ctx context.Context, taskID, limit, offset int) ([]domain.ScanResultResponse, int64, error) {
	if limit < 20 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	results, err := s.queries.ListScanResults(ctx, db.ListScanResultsParams{
		Column1: int64(taskID), TaskID: int64(taskID), Column3: "", Ip: "", Limit: int64(limit), Offset: int64(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.queries.CountScanResults(ctx, db.CountScanResultsParams{Column1: int64(taskID), TaskID: int64(taskID)})
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
	resp := domain.ScanTaskResponse{
		ID:              t.ID,
		Name:            t.Name,
		Targets:         t.Targets,
		CronExpr:        t.CronExpr,
		PipelineConfig:  t.PipelineConfig,
		GlobalLabels:    t.GlobalLabels,
		Timeout:         int(t.Timeout),
		ConcurrentHosts: int(t.ConcurrentHosts),
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
