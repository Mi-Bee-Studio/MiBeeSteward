// Package scheduler wraps go-co-op/gocron to run scan tasks on cron schedules.
// It is the v2 replacement for the legacy scanner.ScanScheduler.
//
// Design (preserved from v1, which was sound):
//   - The DB (scan_tasks rows) is the source of truth; gocron state is ephemeral
//     and re-hydrated on Start().
//   - Each task runs in singleton-reschedule mode (overlapping runs of the same
//     task are dropped, not queued) so a slow /24 can't pile up.
//   - Each run gets a context.Background()-derived, per-task cancelable context
//     so scans outlive any request and can be cancelled via CancelTask.
//   - Stale "running" runs older than 1h are marked failed on startup.
//
// The scheduler delegates actual scanning to a ScanFunc, which the routes layer
// binds to runner.Runner.Run. This keeps scheduler free of engine/runner imports.
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-co-op/gocron/v2"

	"mibee-steward/internal/db"
)

// ScanFunc executes one scan task. It is invoked by the scheduler on each cron
// tick; implementations (runner.Runner.Run) handle run/result persistence and
// the device bridge. timeout/concurrentHosts carry the task's tuning.
type ScanFunc func(ctx context.Context, taskID int64, targets string, timeout time.Duration, concurrentHosts int)

// Scheduler manages cron-driven scan tasks.
type Scheduler struct {
	scheduler   gocron.Scheduler
	queries     *db.Queries
	dbConn      *sql.DB
	scanFunc    ScanFunc
	logger      *slog.Logger
	mu          sync.Mutex
	jobMap      map[int64]gocron.Job
	cancelFuncs map[int64]context.CancelFunc
	started     bool
	stopCh      chan struct{} // closed by Stop to terminate the stale-run sweeper
	staleSweepInterval time.Duration
}

// New constructs a Scheduler. scanFunc is invoked per cron tick.
func New(queries *db.Queries, dbConn *sql.DB, scanFn ScanFunc, logger *slog.Logger) (*Scheduler, error) {
	s, err := gocron.NewScheduler(gocron.WithStopTimeout(30 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("create gocron scheduler: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	if scanFn == nil {
		scanFn = func(context.Context, int64, string, time.Duration, int) {} // no-op safe default
	}
	return &Scheduler{
		scheduler:          s,
		queries:            queries,
		dbConn:             dbConn,
		scanFunc:           scanFn,
		logger:             logger,
		jobMap:             make(map[int64]gocron.Job),
		cancelFuncs:        make(map[int64]context.CancelFunc),
		stopCh:             make(chan struct{}),
		staleSweepInterval: 10 * time.Minute,
	}, nil
}

// Start re-hydrates jobs from enabled scan_tasks and begins cron firing.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	// Mark stale runs failed (>1h old "running").
	s.cleanupStaleRuns(ctx)

	tasks, err := s.queries.ListEnabledScanTasks(ctx)
	if err != nil {
		s.logger.Error("scheduler: list enabled tasks failed", "error", err)
	} else {
		for _, t := range tasks {
			if err := s.registerJob(t.ID, t.CronExpr, t.Targets); err != nil {
				s.logger.Error("scheduler: register job failed", "task_id", t.ID, "error", err)
			}
		}
	}
	s.started = true
	s.scheduler.Start()
	s.logger.Info("scheduler started", "jobs", len(s.jobMap))

	// Periodic stale-run sweeper. Without this, a run that hangs (e.g. a probe
	// stuck on an unresponsive host) stays status='running' forever, and because
	// jobs run in singleton-reschedule mode, every subsequent cron tick / manual
	// trigger for that task is silently dropped. Sweeping every 10min marks
	// >1h-old 'running' rows as failed so the task can fire again.
	go s.staleRunLoop()
}

// Stop shuts down the scheduler, waiting up to 30s for in-flight jobs.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.started = false
	s.mu.Unlock()
	// Signal the stale-run sweeper to exit before shutting down gocron.
	select {
	case <-s.stopCh:
		// already closed (e.g. double Stop)
	default:
		close(s.stopCh)
	}
	if err := s.scheduler.Shutdown(); err != nil {
		s.logger.Error("scheduler shutdown error", "error", err)
	}
}

// AddJob registers or replaces the cron job for a task.
func (s *Scheduler) AddJob(taskID int64, cronExpr, targets string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeJobLocked(taskID)
	return s.registerJob(taskID, cronExpr, targets)
}

// RemoveJob removes the cron job for a task (no-op if absent).
func (s *Scheduler) RemoveJob(taskID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeJobLocked(taskID)
}

// UpdateJob is an alias for AddJob (replace on config change).
func (s *Scheduler) UpdateJob(taskID int64, cronExpr, targets string) error {
	return s.AddJob(taskID, cronExpr, targets)
}

// TriggerNow fires the task's job asynchronously (fire-and-forget).
func (s *Scheduler) TriggerNow(taskID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobMap[taskID]
	if !ok {
		return fmt.Errorf("no job registered for task %d", taskID)
	}
	return j.RunNow()
}

// CancelTask cancels an in-flight run for the task. Returns an error if no run
// is currently active.
func (s *Scheduler) CancelTask(taskID int64) error {
	s.mu.Lock()
	cancel, ok := s.cancelFuncs[taskID]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("no running scan for task %d", taskID)
	}
	cancel()
	return nil
}

// JobCount returns the number of registered jobs (for diagnostics).
func (s *Scheduler) JobCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jobMap)
}

// registerJob creates the gocron job. Caller must hold s.mu.
func (s *Scheduler) registerJob(taskID int64, cronExpr, targets string) error {
	j, err := s.scheduler.NewJob(
		gocron.CronJob(cronExpr, false),
		gocron.NewTask(s.executeScan, taskID, targets),
		gocron.WithTags(fmt.Sprintf("scan-task-%d", taskID)),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		return fmt.Errorf("register cron job task %d: %w", taskID, err)
	}
	s.jobMap[taskID] = j
	return nil
}

// removeJobLocked removes the job; caller holds s.mu.
func (s *Scheduler) removeJobLocked(taskID int64) {
	if j, ok := s.jobMap[taskID]; ok {
		_ = s.scheduler.RemoveJob(j.ID())
		delete(s.jobMap, taskID)
	}
}

// executeScan is the per-job runtime invoked by gocron. It loads the task's
// timeout/concurrency, then calls scanFunc under a cancelable context.
func (s *Scheduler) executeScan(taskID int64, targets string) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancelFuncs[taskID] = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.cancelFuncs, taskID)
		s.mu.Unlock()
		if r := recover(); r != nil {
			s.logger.Error("scheduler: scan panic recovered", "task_id", taskID, "panic", r)
		}
	}()

	// Load the task to read its timeout/concurrency tuning.
	task, err := s.queries.GetScanTask(ctx, taskID)
	if err != nil {
		s.logger.Error("scheduler: load task failed", "task_id", taskID, "error", err)
		return
	}
	timeout := time.Duration(task.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	concurrent := int(task.ConcurrentHosts)
	if concurrent <= 0 {
		concurrent = 50
	}

	start := time.Now()
	s.logger.Info("scan job started", "task_id", taskID, "targets", targets)
	s.scanFunc(ctx, taskID, targets, timeout, concurrent)
	s.logger.Info("scan job completed", "task_id", taskID, "duration", time.Since(start))
}

// cleanupStaleRuns marks "running" runs older than 1h as failed (server crashed
// mid-scan). Caller holds s.mu via Start.
func (s *Scheduler) cleanupStaleRuns(ctx context.Context) {
	if s.dbConn == nil {
		return
	}
	res, err := s.dbConn.ExecContext(ctx,
		`UPDATE scan_task_runs SET status='failed', finished_at=datetime('now'),
		 error_message='stale run cleaned up on startup'
		 WHERE status='running' AND started_at < datetime('now','-1 hour')`)
	if err != nil {
		s.logger.Warn("scheduler: stale-run cleanup failed", "error", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.logger.Info("scheduler: cleaned up stale runs", "count", n)
	}
}

// staleRunLoop periodically re-runs cleanupStaleRuns while the scheduler is
// active. This recovers tasks whose latest run is stuck 'running' (which would
// otherwise hold the singleton-reschedule limiter forever and silently drop all
// subsequent triggers). Started by Start, stopped by close(s.stopCh).
func (s *Scheduler) staleRunLoop() {
	ticker := time.NewTicker(s.staleSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			// Use a background ctx — the run-loop outlives any request and the
			// scheduler intentionally survives request cancellation.
			s.cleanupStaleRuns(context.Background())
		}
	}
}

