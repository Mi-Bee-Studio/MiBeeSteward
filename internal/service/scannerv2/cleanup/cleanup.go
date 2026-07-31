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
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// Service is the unified retention sweeper. One ticker drives pruning across
// every high-volume detail table; each table's window comes from RetentionConfig.
type Service struct {
	queries          *db.Queries // main DB (scan_results, scan_task_runs, audit_logs, notification_log, service_evidence)
	heartbeatQueries *db.Queries // dedicated heartbeat DB (heartbeat_results lives in a separate file)
	heartbeatDB      *sql.DB     // raw conn to heartbeat.db, for device_liveness RFC3339-bound deletes (sqlc passes time.Time which sorts wrong vs stored RFC3339 text)
	mainDB           *sql.DB     // raw conn to the main DB, for the device-pruning DELETE + change_log emit (sqlc has no batched device delete)
	cfg              config.RetentionConfig
	interval         time.Duration
	batch            int64
	logger           *slog.Logger
	cancel           context.CancelFunc
	done             chan struct{}
}

// New constructs the retention sweeper from config. heartbeatQueries is the
// sqlc Queries bound to the dedicated heartbeat.db (nil ⇒ heartbeat pruning
// is skipped, for tests/main-DB-only contexts). heartbeatDB is the raw
// connection for the RFC3339-bound device_liveness delete (nil ⇒ skipped).
// mainDB is the raw main-DB connection for the silent-device prune (nil ⇒
// device pruning is skipped — tests that don't exercise it). SweepIntervalHours
// <=0 and BatchSize<=0 are defended in config.normalizeRetention.
func New(queries *db.Queries, heartbeatQueries *db.Queries, heartbeatDB, mainDB *sql.DB, cfg config.RetentionConfig) *Service {
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
		heartbeatDB:      heartbeatDB,
		mainDB:           mainDB,
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
	s.pruneDeviceLiveness(ctx)
	s.pruneScanResults(ctx)
	s.pruneScanTaskRuns(ctx)
	s.pruneAuditLogs(ctx)
	s.pruneNotificationLogs(ctx)
	s.pruneServiceEvidence(ctx)
	s.pruneChangeLog(ctx)
	s.pruneDeviceNeighbors(ctx)
	s.pruneHostServices(ctx)
	s.pruneHostTLSCerts(ctx)
	s.pruneSilentDevices(ctx)
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

// pruneDeviceLiveness prunes the per-device verdict series. It lives in the
// same heartbeat.db as heartbeat_results, so it shares the heartbeatQueries
// binding. The series is disposable (devices.status is source of truth), so the
// window can be tight; it mirrors heartbeat_results (7d) to cover the longest
// multi-period window the change engine queries.
//
// The cutoff is formatted as RFC3339 (not passed as time.Time via sqlc) because
// device_liveness.checked_at is stored as RFC3339 TEXT: a time.Time arg
// serializes via modernc to a different string shape that compares wrong. The
// raw SQL mirrors the sqlc query but formats the bound in Go.
func (s *Service) pruneDeviceLiveness(ctx context.Context) {
	if s.heartbeatQueries == nil {
		return
	}
	days := s.cfg.DeviceLivenessDays
	s.sweepBatched(ctx, "device_liveness", days, func(cut time.Time, limit int64) (int64, error) {
		cutStr := cut.UTC().Format(time.RFC3339)
		res, err := s.heartbeatDB.ExecContext(ctx,
			`DELETE FROM device_liveness WHERE rowid IN (
				SELECT rowid FROM device_liveness WHERE checked_at < ? LIMIT ?)`,
			cutStr, limit)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
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

// silentDeviceCutoff returns the cutoff time for the "no heartbeat" silent-
// device prune, keyed by MAC presence. macCutoff uses SilentDeviceDaysMAC
// (default 7d); noMacCutoff uses SilentDeviceHoursNoMAC (default 24h). A field
// of 0 means "use the default" (normalizeRetention fills them), never "disabled".
func silentDeviceCutoffs(cfg config.RetentionConfig) (macCutoff, noMacCutoff time.Time) {
	now := time.Now()
	macDays := cfg.SilentDeviceDaysMAC
	if macDays <= 0 {
		macDays = 7
	}
	noMacHours := cfg.SilentDeviceHoursNoMAC
	if noMacHours <= 0 {
		noMacHours = 24
	}
	return now.AddDate(0, 0, -macDays), now.Add(time.Duration(-noMacHours) * time.Hour)
}

// pruneSilentDevices physically deletes scanner-discovered devices that have had
// no heartbeat for longer than the configured window (issue #117). Two cases:
//
//  1. Silent device: a scanner_v2 device whose status is 'offline' and whose
//     offline_since is older than the threshold — 7d if it has a MAC (a real
//     asset that may be genuinely gone), 24h if it has no MAC (an unreliable
//     mac-less identity that's likely a transient/duplicate discovery).
//  2. Roamed orphan: a scanner_v2 device whose MAC also exists ONLINE in another
//     network (it DHCP-roamed) AND whose offline_since is older than
//     roamedOrphanWindow — the device has a live copy elsewhere, so this row is
//     a stale old-network leftover. The window is tighter than the silent
//     window (the online copy proves the asset still exists).
//
// Manual devices (scan_source != 'scanner_v2') are NEVER auto-deleted — a human
// added them, a human removes them (CMDB semantics). Each deletion is logged to
// change_log as device_removed (with a before snapshot + reason) BEFORE the
// DELETE, so the audit trail survives the CASCADE. Skipped entirely when mainDB
// is nil (tests that don't exercise device pruning).
//
// NOTE on cutoff formatting: offline_since is stored as RFC3339-ish TEXT (the
// heartbeat/scan writers pass Go time.Time, which modernc serializes with a
// space + monotonic suffix; the silent-device tests store RFC3339Nano). A
// string-comparison `< ?` therefore needs the cutoff bound in a matching
// RFC3339 shape, NOT a raw time.Time (which would sort wrong). Mirrors the
// documented device_liveness prune (pruneDeviceLiveness). We use RFC3339Nano
// for sub-second precision.
func (s *Service) pruneSilentDevices(ctx context.Context) {
	if s.mainDB == nil {
		return
	}
	macCut, noMacCut := silentDeviceCutoffs(s.cfg)
	// The roamed-orphan window: ~5 probe cycles at the 30s default tick ≈ 2.5min is
	// too aggressive (a scan-in-progress could briefly show the old row offline).
	// Use a safe floor (10min) so a genuine roam settles before the orphan is cut.
	const roamedOrphanWindow = 10 * time.Minute
	roamedCut := time.Now().Add(-roamedOrphanWindow)
	// Format cutoffs as RFC3339Nano so the string `<` comparison against the
	// stored offline_since TEXT sorts correctly (see the NOTE above).
	macCutStr := macCut.UTC().Format(time.RFC3339Nano)
	noMacCutStr := noMacCut.UTC().Format(time.RFC3339Nano)
	roamedCutStr := roamedCut.UTC().Format(time.RFC3339Nano)

	var totalDeleted int64
	for {
		if ctx.Err() != nil {
			s.logger.Info("cleanup: silent-device sweep cancelled", "deleted_so_far", totalDeleted)
			return
		}
		// Select one batch of candidate rows (id + identity for the change_log
		// before-snapshot). The DELETE happens row-by-row after the log write so a
		// failure on one row doesn't lose the audit trail for the others.
		rows, err := s.mainDB.QueryContext(ctx, `
			SELECT id, device_uuid, name, type, brand, model, mac_address, ip_address,
			       network_id, offline_since,
			   CASE
			         WHEN mac_address != '' AND offline_since < ? THEN 'silent_mac'
			         WHEN mac_address = ''  AND offline_since < ? THEN 'silent_no_mac'
			         WHEN mac_address != '' AND offline_since < ? AND EXISTS (
			           SELECT 1 FROM devices d2
			           WHERE d2.mac_address = devices.mac_address
			             AND d2.id != devices.id
			             AND d2.status = 'online'
			         ) THEN 'roamed_orphan'
			       END AS reason
			FROM devices
			WHERE scan_source = 'scanner_v2'
			  AND status = 'offline'
			  AND offline_since IS NOT NULL
			  AND reason IS NOT NULL
			LIMIT ?`,
			macCutStr, noMacCutStr, roamedCutStr, s.batch)
		if err != nil {
			s.logger.Warn("cleanup: silent-device select failed", "error", err)
			return
		}
		type candidate struct {
			id           int64
			uuid         string
			name         string
			devType      string
			brand, model string
			mac, ip      string
			networkID    sql.NullInt64
			offlineSince sql.NullTime
			reason       string
		}
		var batch []candidate
		for rows.Next() {
			var c candidate
			var netID sql.NullInt64
			if err := rows.Scan(&c.id, &c.uuid, &c.name, &c.devType, &c.brand, &c.model,
				&c.mac, &c.ip, &netID, &c.offlineSince, &c.reason); err != nil {
				s.logger.Warn("cleanup: silent-device scan failed", "error", err)
				break
			}
			c.networkID = netID
			batch = append(batch, c)
		}
		rows.Close()

		for _, c := range batch {
			s.logDeviceRemoved(ctx, c.id, c.uuid, c.name, c.devType, c.brand, c.model,
				c.mac, c.ip, c.networkID, c.reason)
			if err := s.execWithBusyRetry(ctx, `DELETE FROM devices WHERE id = ?`, c.id); err != nil {
				s.logger.Warn("cleanup: silent-device delete failed",
					"device_id", c.id, "ip", c.ip, "mac", c.mac, "reason", c.reason, "error", err)
				continue
			}
			totalDeleted++
		}

		// Under batch size ⇒ no more candidates this pass.
		if int64(len(batch)) < s.batch {
			break
		}
	}
	if totalDeleted > 0 {
		s.logger.Info("cleanup: pruned silent devices",
			"count", totalDeleted,
			"silent_mac_days", s.cfg.SilentDeviceDaysMAC,
			"silent_no_mac_hours", s.cfg.SilentDeviceHoursNoMAC)
	}
}

// logDeviceRemoved writes a device_removed audit row to change_log BEFORE the
// device row is deleted (so the before snapshot is captured while the row still
// exists; CASCADE will then clean up FK children but leave this change_log row —
// change_log.entity_id has no FK, intentionally, so device history survives the
// device). Minimal JSON before_data (identity fields) — not the full snapshot,
// since the device is being deleted anyway and the purpose is a "what got
// pruned and why" trail, not a full restore record.
func (s *Service) logDeviceRemoved(ctx context.Context, id int64, uuid, name, devType, brand, model, mac, ip string, networkID sql.NullInt64, reason string) {
	before := fmt.Sprintf(
		`{"name":%q,"type":%q,"brand":%q,"model":%q,"mac_address":%q,"ip_address":%q,"device_uuid":%q,"status":"offline"}`,
		name, devType, brand, model, mac, ip, uuid)
	var netID any
	if networkID.Valid {
		netID = networkID.Int64
	}
	if err := s.execWithBusyRetry(ctx, `
		INSERT INTO change_log (agent_id, network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at)
		VALUES (?, ?, 'device_removed', 'device', ?, ?, NULL, CURRENT_TIMESTAMP)`,
		reason, netID, id, before); err != nil {
		s.logger.Warn("cleanup: log device_removed failed", "device_id", id, "error", err)
	}
}

// execWithBusyRetry runs a write statement against mainDB, retrying on
// SQLITE_BUSY with a short backoff. This stands in for the busy_timeout PRAGMA
// that the connection pool does NOT reliably apply to every pooled connection
// (Go's database/sql opens fresh connections with default pragmas, so a write
// that lands on a fresh connection gets an immediate BUSY instead of waiting).
// The cleanup sweeper writes many rows in sequence while the heartbeat
// syncStatusLoop (30s) and scanner may hold the write lock; without retry, ~7%
// of deletes fail on a busy sweep. Retries up to ~5s total (mirroring the
// intended busy_timeout=5000). Non-BUSY errors are returned immediately.
func (s *Service) execWithBusyRetry(ctx context.Context, query string, args ...any) error {
	const (
		maxAttempts = 6
		initialWait = 100 * time.Millisecond
	)
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, err := s.mainDB.ExecContext(ctx, query, args...)
		if err == nil {
			return nil
		}
		lastErr = err
		// Retry only on SQLITE_BUSY (code 5) / "database is locked". Other
		// errors (constraint, syntax) fail fast.
		if !strings.Contains(err.Error(), "busy") && !strings.Contains(err.Error(), "locked") {
			return err
		}
		wait := initialWait * (1 << attempt) // 100ms, 200ms, 400ms, 800ms, 1.6s
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return lastErr
}
