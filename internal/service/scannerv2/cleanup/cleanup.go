// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package cleanup runs the periodic retention sweep that prunes high-volume
// detail tables so they don't grow unbounded.
//
// History: this used to delete only scan_results. The real data-volume problem
// is broader — heartbeat_results alone accumulates ~270k rows/day, and
// scan_task_runs / audit_logs / notification_log / service_evidence had no
// pruning at all. The sweep now covers all six detail tables, each with its
// own retention window, and deletes in batches to avoid locking the database
// for long stretches on large tables (a single DELETE on a million-row table
// holds the write lock far too long and bloats WAL).
package cleanup

import (
	"context"
	"log/slog"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// Service is the unified retention sweeper. One ticker drives pruning across
// every high-volume detail table; each table's window comes from RetentionConfig.
type Service struct {
	queries          *db.Queries // main DB (scan_results, scan_task_runs, audit_logs, notification_log, service_evidence)
	heartbeatQueries *db.Queries // dedicated heartbeat DB (heartbeat_results lives in a separate file)
	cfg              config.RetentionConfig
	interval         time.Duration
	batch            int64
	logger           *slog.Logger
	cancel           context.CancelFunc
	done             chan struct{}
}

// New constructs the retention sweeper from config. heartbeatQueries is the
// sqlc Queries bound to the dedicated heartbeat.db (nil ⇒ heartbeat pruning
// is skipped, for tests/main-DB-only contexts). SweepIntervalHours<=0 and
// BatchSize<=0 are defended in config.normalizeRetention.
func New(queries *db.Queries, heartbeatQueries *db.Queries, cfg config.RetentionConfig) *Service {
	interval := time.Duration(cfg.SweepIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	batch := int64(cfg.BatchSize)
	if batch <= 0 {
		batch = 5000
	}
	return &Service{
		queries:          queries,
		heartbeatQueries: heartbeatQueries,
		cfg:              cfg,
		interval:         interval,
		batch:            batch,
		logger:           slog.Default(),
		done:             make(chan struct{}),
	}
}

// Start runs one sweep immediately, then on every interval tick, until Stop.
func (s *Service) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go func() {
		defer close(s.done)
		s.logger.Info("retention sweeper starting",
			"interval", s.interval,
			"batch", s.batch,
			"heartbeat_days", s.cfg.HeartbeatResultsDays,
			"scan_results_days", s.cfg.ScanResultsDays,
			"audit_days", s.cfg.AuditLogsDays,
		)
		s.runOnce(ctx) // sweep on startup so a long-stopped server catches up immediately
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

// Stop signals the sweep loop to exit and waits for it.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	<-s.done
}

// runOnce prunes every detail table whose retention window is configured.
// Each table is independent: a failure on one (e.g. a missing column) is logged
// and skipped so the sweep still cleans the others.
func (s *Service) runOnce(ctx context.Context) {
	s.pruneHeartbeatResults(ctx)
	s.pruneScanResults(ctx)
	s.pruneScanTaskRuns(ctx)
	s.pruneAuditLogs(ctx)
	s.pruneNotificationLogs(ctx)
	s.pruneServiceEvidence(ctx)
	s.pruneChangeLog(ctx)
	s.pruneDeviceNeighbors(ctx)
	s.pruneHostServices(ctx)
	s.pruneHostTLSCerts(ctx)
}

// cutoff returns now - retentionDays, or a zero time if days<=0 (which would
// otherwise delete EVERYTHING). config.normalizeRetention fills defaults, but
// this guard keeps a misconfigured sweep from wiping a table.
func cutoff(days int) time.Time {
	if days <= 0 {
		return time.Time{} // zero time matches nothing (all rows are after 0001-01-01... except real ones)
	}
	return time.Now().AddDate(0, 0, -days)
}

// sweepBatched loops the batched DELETE until a batch affects fewer rows than
// batchSize — the signal that the backlog for this cutoff is exhausted. Returns
// the total rows deleted across all batches.
func (s *Service) sweepBatched(ctx context.Context, table string, days int, del func(cutoff time.Time, limit int64) (int64, error)) int64 {
	cut := cutoff(days)
	if cut.IsZero() {
		// days<=0 means "not configured" — leave the table alone, never delete-all.
		return 0
	}
	var total int64
	for {
		if ctx.Err() != nil {
			s.logger.Info("cleanup: sweep cancelled mid-table", "table", table, "deleted_so_far", total)
			return total
		}
		n, err := del(cut, s.batch)
		if err != nil {
			s.logger.Warn("cleanup: batched delete failed", "table", table, "error", err, "deleted_so_far", total)
			return total
		}
		total += n
		if n < s.batch {
			break // under batch size ⇒ nothing older left for this cutoff
		}
	}
	if total > 0 {
		s.logger.Info("cleanup: pruned old rows", "table", table, "count", total, "retention_days", days)
	} else {
		s.logger.Debug("cleanup: nothing to prune", "table", table, "retention_days", days)
	}
	return total
}

func (s *Service) pruneHeartbeatResults(ctx context.Context) {
	if s.heartbeatQueries == nil {
		return // no heartbeat store configured (tests/main-DB-only)
	}
	days := s.cfg.HeartbeatResultsDays
	s.sweepBatched(ctx, "heartbeat_results", days, func(cut time.Time, limit int64) (int64, error) {
		return s.heartbeatQueries.DeleteOlderThanBatched(ctx, db.DeleteOlderThanBatchedParams{
			CheckedAt: cut,
			Limit:     limit,
		})
	})
}

func (s *Service) pruneScanResults(ctx context.Context) {
	days := s.cfg.ScanResultsDays
	s.sweepBatched(ctx, "scan_results", days, func(cut time.Time, limit int64) (int64, error) {
		return s.queries.DeleteScanResultsOlderThanBatched(ctx, db.DeleteScanResultsOlderThanBatchedParams{
			ScannedAt: cut,
			Limit:     limit,
		})
	})
}

func (s *Service) pruneScanTaskRuns(ctx context.Context) {
	days := s.cfg.ScanTaskRunsDays
	s.sweepBatched(ctx, "scan_task_runs", days, func(cut time.Time, limit int64) (int64, error) {
		return s.queries.DeleteScanTaskRunsOlderThanBatched(ctx, db.DeleteScanTaskRunsOlderThanBatchedParams{
			CreatedAt: cut,
			Limit:     limit,
		})
	})
}

func (s *Service) pruneAuditLogs(ctx context.Context) {
	days := s.cfg.AuditLogsDays
	s.sweepBatched(ctx, "audit_logs", days, func(cut time.Time, limit int64) (int64, error) {
		// audit_logs.created_at is a nullable DATETIME, so sqlc emits *time.Time.
		return s.queries.DeleteAuditLogsOlderThanBatched(ctx, db.DeleteAuditLogsOlderThanBatchedParams{
			CreatedAt: &cut,
			Limit:     limit,
		})
	})
}

func (s *Service) pruneNotificationLogs(ctx context.Context) {
	days := s.cfg.NotificationLogDays
	s.sweepBatched(ctx, "notification_log", days, func(cut time.Time, limit int64) (int64, error) {
		return s.queries.DeleteNotificationLogsOlderThanBatched(ctx, db.DeleteNotificationLogsOlderThanBatchedParams{
			SentAt: cut,
			Limit:  limit,
		})
	})
}

func (s *Service) pruneServiceEvidence(ctx context.Context) {
	days := s.cfg.ServiceEvidenceDays
	s.sweepBatched(ctx, "service_evidence", days, func(cut time.Time, limit int64) (int64, error) {
		return s.queries.DeleteServiceEvidenceOlderThanBatched(ctx, db.DeleteServiceEvidenceOlderThanBatchedParams{
			ObservedAt: cut,
			Limit:      limit,
		})
	})
}

// pruneChangeLog prunes change-detection events (device_added/changed/lost)
// older than the retention window. change_log grows ~one row per real change
// per scan, so it accumulates faster than audit but slower than heartbeat.
func (s *Service) pruneChangeLog(ctx context.Context) {
	days := s.cfg.ChangeLogDays
	s.sweepBatched(ctx, "change_log", days, func(cut time.Time, limit int64) (int64, error) {
		return s.queries.DeleteChangeLogOlderThanBatched(ctx, db.DeleteChangeLogOlderThanBatchedParams{
			DetectedAt: cut,
			Limit:      limit,
		})
	})
}

// pruneDeviceNeighbors prunes L2-adjacency edges (Bridge-MIB / LLDP) older than
// the retention window. device_neighbors is low-volume (one row per real
// adjacency, refreshed by upsert) but edges for gone-silent adjacencies linger;
// the longer default (90d) reflects its topology-history value.
func (s *Service) pruneDeviceNeighbors(ctx context.Context) {
	days := s.cfg.DeviceNeighborsDays
	s.sweepBatched(ctx, "device_neighbors", days, func(cut time.Time, limit int64) (int64, error) {
		// last_seen is nullable; pass &cut (a *time.Time) so the bound is the
		// cutoff and NULL last_seen rows are left alone (SQL NULL < x is unknown).
		return s.queries.DeleteDeviceNeighborsOlderThanBatched(ctx, db.DeleteDeviceNeighborsOlderThanBatchedParams{
			LastSeen: &cut,
			Limit:    limit,
		})
	})
}

// pruneHostServices prunes classified service identities for hosts that haven't
// been seen within the retention window. host_services is upserted (not
// appended), so it doesn't grow per-scan — but rows for gone-silent hosts are
// never refreshed and linger; this reclaims them.
func (s *Service) pruneHostServices(ctx context.Context) {
	days := s.cfg.HostServicesDays
	s.sweepBatched(ctx, "host_services", days, func(cut time.Time, limit int64) (int64, error) {
		return s.queries.DeleteHostServicesStaleBatched(ctx, db.DeleteHostServicesStaleBatchedParams{
			UpdatedAt: cut,
			Limit:     limit,
		})
	})
}

// pruneHostTLSCerts prunes the TLS certificate chain rows for hosts that haven't
// been seen within the retention window. host_tls_certs is replaced per
// (ip, port) on each successful scan, but a gone-silent host leaves its last
// cert chain behind; this reclaims those stale rows. PEM payload is a few KB
// per row, so this also bounds storage growth from cert rotation history.
func (s *Service) pruneHostTLSCerts(ctx context.Context) {
	days := s.cfg.HostTLSCertsDays
	s.sweepBatched(ctx, "host_tls_certs", days, func(cut time.Time, limit int64) (int64, error) {
		return s.queries.DeleteHostTLSCertsStaleBatched(ctx, db.DeleteHostTLSCertsStaleBatchedParams{
			UpdatedAt: cut,
			Limit:     limit,
		})
	})
}
