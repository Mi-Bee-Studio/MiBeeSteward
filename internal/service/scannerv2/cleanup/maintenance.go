// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, copy, modify, and redistribute it
// under those terms; see LICENSE for the full text. A commercial license is
// available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package cleanup

import (
	"context"
	"database/sql"
	"os"

	"mibee-steward/internal/metrics"
)

// runMaintenance is the storage-health pass of the sweeper cycle (#280). It
// runs AFTER pruning (which is what creates free pages worth checkpointing):
//
//   - PRAGMA wal_checkpoint(TRUNCATE) folds the WAL back into the DB file so
//     the -wal sidecar returns to zero instead of drifting upward forever.
//     Busy (readers active) is normal — the call simply makes no progress and
//     the next pass tries again; a checkpoint is never worth blocking on.
//   - PRAGMA optimize updates SQLite's internal statistics (recommended after
//     bulk deletes; cheap and self-limiting).
//   - File sizes + high-volume table row counts are sampled into
//     mibee_db_size_bytes / mibee_db_table_rows — the growth baseline for
//     capacity planning and the db-growth alert (#279).
//
// Everything is best-effort: a failed step logs at Debug/Warn and never fails
// the sweep.
func (s *Service) runMaintenance(ctx context.Context) {
	if s.mainDB != nil {
		s.maintainOne(ctx, "main", s.mainDB)
	}
	if s.heartbeatDB != nil {
		s.maintainOne(ctx, "heartbeat", s.heartbeatDB)
	}
}

// mainDBTables / heartbeatDBTables are the row-count sample sets. Counting is
// a full-table scan on SQLite, so these are the tables that actually matter
// for growth monitoring — not every table.
var (
	mainDBTables      = []string{"devices", "scan_results", "scan_task_runs", "host_services", "service_evidence", "audit_logs", "scan_snapshots", "change_log"}
	heartbeatDBTables = []string{"heartbeat_results", "device_liveness"}
)

func (s *Service) maintainOne(ctx context.Context, name string, conn *sql.DB) {
	if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		// BUSY just means a reader held the WAL; not an error worth noise.
		s.logger.Debug("maintenance: wal checkpoint made no progress", "db", name, "error", err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA optimize`); err != nil {
		s.logger.Warn("maintenance: optimize failed", "db", name, "error", err)
	}

	// File sizes via PRAGMA database_list (the handle doesn't know its path).
	rows, err := conn.QueryContext(ctx, `PRAGMA database_list`)
	if err == nil {
		var seq int
		var dbName, dbFile string
		for rows.Next() {
			if err := rows.Scan(&seq, &dbName, &dbFile); err != nil {
				break
			}
			if dbFile == "" { // :memory: / temp
				continue
			}
			for kind, path := range map[string]string{
				"db":  dbFile,
				"wal": dbFile + "-wal",
			} {
				if fi, err := os.Stat(path); err == nil {
					metrics.MibeeDBSizeBytes.WithLabelValues(name, kind).Set(float64(fi.Size()))
				} else {
					// No WAL file = checkpoint fully truncated; report 0
					// instead of leaving a stale value.
					metrics.MibeeDBSizeBytes.WithLabelValues(name, kind).Set(0)
				}
			}
		}
		rows.Close()
	}

	tables := mainDBTables
	if name == "heartbeat" {
		tables = heartbeatDBTables
	}
	for _, table := range tables {
		var n int64
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
			// A table that doesn't exist in this build/schema edition is fine.
			s.logger.Debug("maintenance: row count skipped", "db", name, "table", table, "error", err)
			continue
		}
		metrics.MibeeDBTableRows.WithLabelValues(name, table).Set(float64(n))
	}
}
