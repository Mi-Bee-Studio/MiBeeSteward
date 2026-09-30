// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. You can use, copy, modify, and
// redistribute it under those terms; see LICENSE for the full text. A
// commercial license is available for use cases the AGPLv3 does not
// accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// sweepStaleAgentData prunes the agent's LOCAL mini-DB so it cannot grow
// unbounded on a long-lived box. The center is the authoritative registry and
// already runs its own retention sweeps; the agent previously had NONE, and a
// field rig showed the shadow devices table keeping seven silently-dead rows
// (MAC-less identities last seen days earlier) plus a scan_results table at
// 95 MB after a week.
//
// Mirrors the center's retention semantics (config.example.yaml retention):
//   - devices: MAC-less silent identities pruned after 24h (an identity
//     without a MAC is unreliable), MAC-bearing after 7d (a real asset may be
//     gone a while). MAC = mac_address OR scan_attributes' mac (the bridge
//     may only have written the structured one).
//   - scan_results: keep 72h only. These rows are a LOCAL evidence cache the
//     center already ingested; a field rig showed ~10.5k rows/day (91k rows /
//     116 MB on 2026-09-30), so the former 14d window meant a ~180 MB
//     steady-state file on a small flash box for zero reader value.
//   - scan_task_runs: keep 30d (center's scan_task_runs_days default).
func sweepStaleAgentData(ctx context.Context, db *sql.DB, logger *slog.Logger) {
	if db == nil {
		return
	}
	statements := []struct {
		name string
		sql  string
	}{
		{"devices_silent_mac_7d", `
			DELETE FROM devices
			WHERE last_seen IS NOT NULL AND last_seen < datetime('now', '-7 days')
			   OR offline_since IS NOT NULL AND offline_since < datetime('now', '-7 days')`},
		{"devices_silent_no_mac_24h", `
			DELETE FROM devices
			WHERE (mac_address IS NULL OR mac_address = '')
			  AND (json_extract(scan_attributes, '$.mac') IS NULL
			       OR json_extract(scan_attributes, '$.mac') = '')
			  AND last_seen IS NOT NULL AND last_seen < datetime('now', '-24 hours')`},
		{"scan_results_72h", `
			DELETE FROM scan_results WHERE scanned_at < datetime('now', '-72 hours')`},
		{"scan_task_runs_30d", `
			DELETE FROM scan_task_runs WHERE created_at < datetime('now', '-30 days')`},
	}
	var totalPruned int64
	for _, s := range statements {
		res, err := db.ExecContext(ctx, s.sql)
		if err != nil {
			logger.Warn("agent sweep failed", "step", s.name, "error", err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			logger.Info("agent sweep pruned", "step", s.name, "rows", n)
			totalPruned += n
		}
	}
	// SQLite never shrinks a file on DELETE — without this the rig's agent.db
	// stays at its high-water mark (116 MB observed 2026-09-30) no matter how
	// much the sweep prunes. VACUUM only after a substantial prune so the
	// rewrite cost is rare; best-effort (fails harmlessly under contention).
	if totalPruned >= 1000 {
		if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
			logger.Warn("agent sweep vacuum failed", "error", err)
		} else {
			logger.Info("agent sweep vacuumed", "pruned_rows", totalPruned)
		}
	}
}

// startAgentSweeper runs sweepStaleAgentData immediately and then every
// interval (6h, matching the center's retention sweep cadence) until ctx is
// cancelled.
func startAgentSweeper(ctx context.Context, db *sql.DB, logger *slog.Logger) {
	go func() {
		sweepStaleAgentData(ctx, db, logger)
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweepStaleAgentData(ctx, db, logger)
			}
		}
	}()
}
