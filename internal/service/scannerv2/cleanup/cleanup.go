// Package cleanup prunes aged-out scan results on a fixed interval. It is the
// v2 replacement for the legacy scanner.CleanupService, reusing the same
// DeleteScanResultsOlderThan sqlc query and the same retention-days semantics.
package cleanup

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"mibee-steward/internal/db"
)

// Service deletes scan_results rows older than a retention window, on a ticker.
type Service struct {
	queries       *db.Queries
	retentionDays int
	interval      time.Duration
	logger        *slog.Logger
	cancel        context.CancelFunc
	done          chan struct{}
}

// New constructs a cleanup service. retentionDays<=0 → 30; interval<=0 → 24h.
func New(queries *db.Queries, retentionDays int, interval time.Duration) *Service {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &Service{
		queries:       queries,
		retentionDays: retentionDays,
		interval:      interval,
		logger:        slog.Default(),
		done:          make(chan struct{}),
	}
}

// Start runs one cleanup immediately, then on every interval tick, until Stop.
func (s *Service) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go func() {
		defer close(s.done)
		s.runOnce(ctx)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runOnce(ctx)
			}
		}
	}()
}

// Stop signals the cleanup loop to exit and waits for it.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	<-s.done
}

func (s *Service) runOnce(ctx context.Context) {
	days := strconv.Itoa(s.retentionDays)
	rows, err := s.queries.DeleteScanResultsOlderThan(ctx, &days)
	if err != nil {
		s.logger.Warn("cleanup: delete old scan results failed", "error", err)
		return
	}
	if rows > 0 {
		s.logger.Info("cleanup: pruned old scan results", "count", rows, "retention_days", s.retentionDays)
	}
}
