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
//   - scan_results: keep 14d (center's service_evidence default; these rows
//     are per-task history the center already ingested).
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
		{"scan_results_14d", `
			DELETE FROM scan_results WHERE scanned_at < datetime('now', '-14 days')`},
		{"scan_task_runs_30d", `
			DELETE FROM scan_task_runs WHERE created_at < datetime('now', '-30 days')`},
	}
	for _, s := range statements {
		res, err := db.ExecContext(ctx, s.sql)
		if err != nil {
			logger.Warn("agent sweep failed", "step", s.name, "error", err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			logger.Info("agent sweep pruned", "step", s.name, "rows", n)
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
