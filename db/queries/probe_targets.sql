-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later; see LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: CreateProbeTarget :one
INSERT INTO probe_targets (name, module, target, interval_seconds, timeout_seconds, enabled, notes)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at;

-- name: GetProbeTarget :one
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at
FROM probe_targets
WHERE id = ?;

-- name: GetProbeTargetByName :one
-- Duplicate-name detection for CRUD validation (name is the metric label, so
-- duplicates would make mibee_probe_* series ambiguous).
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at
FROM probe_targets
WHERE name = ?;

-- name: ListProbeTargetsSearch :many
-- Optional case-insensitive substring search over name + target, using the
-- same (? = '') short-circuit idiom as ListScanTasksSearch (INSTR so search
-- terms need no escaping). CountProbeTargetsSearch MUST mirror this WHERE.
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at
FROM probe_targets
WHERE (? = '' OR INSTR(lower(name), lower(?)) > 0 OR INSTR(lower(target), lower(?)) > 0)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountProbeTargetsSearch :one
SELECT COUNT(*)
FROM probe_targets
WHERE (? = '' OR INSTR(lower(name), lower(?)) > 0 OR INSTR(lower(target), lower(?)) > 0);

-- name: UpdateProbeTarget :one
UPDATE probe_targets
SET name = ?, module = ?, target = ?, interval_seconds = ?, timeout_seconds = ?,
    enabled = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at;

-- name: ToggleProbeTargetEnabled :exec
UPDATE probe_targets
SET enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteProbeTarget :execrows
DELETE FROM probe_targets
WHERE id = ?;

-- name: ListEnabledProbeTargets :many
-- The engine re-reads this every tick so CRUD changes apply without restart.
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at
FROM probe_targets
WHERE enabled = 1;

-- name: SetProbeTargetLastResult :exec
-- Denormalizes the newest outcome for the list view. last_run_at is an
-- RFC3339 UTC string (modernc time.Time breaks SQLite date()); it is also
-- the next-due anchor used by the engine on restart.
UPDATE probe_targets
SET last_run_at = ?, last_status = ?, last_latency_ms = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
