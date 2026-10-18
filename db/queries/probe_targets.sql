-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- vantage (#277): the execution plan - 'center' | 'agent:{agent_id}' | 'all'
-- ('all' expands to center + every agent at run time, never stored expanded).
-- Not part of identity: name stays UNIQUE alone.

-- name: CreateProbeTarget :one
INSERT INTO probe_targets (name, module, target, interval_seconds, timeout_seconds, enabled, notes, vantage, options, device_id, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source;

-- name: GetProbeTarget :one
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source
FROM probe_targets
WHERE id = ?;

-- name: GetProbeTargetByName :one
-- Duplicate-name detection for CRUD validation (name is the metric label, so
-- duplicates would make mibee_probe_* series ambiguous).
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source
FROM probe_targets
WHERE name = ?;

-- name: ListProbeTargetsSearch :many
-- Optional case-insensitive substring search over name + target, using the
-- same empty-string short-circuit idiom as ListScanTasksSearch (INSTR so
-- search terms need no escaping). CountProbeTargetsSearch MUST mirror this
-- WHERE.
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source
FROM probe_targets
WHERE (? = '' OR INSTR(lower(name), lower(?)) > 0 OR INSTR(lower(target), lower(?)) > 0)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountProbeTargetsSearch :one
SELECT COUNT(*)
FROM probe_targets
WHERE (? = '' OR INSTR(lower(name), lower(?)) > 0 OR INSTR(lower(target), lower(?)) > 0);

-- name: UpdateProbeTarget :one
-- source is deliberately NOT updatable here: provenance is set at creation
-- and owned by its creator path (manual = user, auto = sweep, system = seed).
UPDATE probe_targets
SET name = ?, module = ?, target = ?, interval_seconds = ?, timeout_seconds = ?,
    enabled = ?, notes = ?, vantage = ?, options = ?, device_id = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source;

-- name: ToggleProbeTargetEnabled :exec
UPDATE probe_targets
SET enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteProbeTarget :execrows
DELETE FROM probe_targets
WHERE id = ?;

-- name: ListEnabledProbeTargets :many
-- The engine re-reads this every tick so CRUD changes apply without restart.
-- Targets whose vantage is agent-only are filtered in the engine (Go), not
-- here: the center engine runs 'center' and 'all' vantages and leaves
-- 'agent:{id}' plans to the agent command channel (#277 step 2).
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source
FROM probe_targets
WHERE enabled = 1;

-- name: SetProbeTargetLastResult :exec
-- Denormalizes the newest outcome for the list view. last_run_at is an
-- RFC3339 UTC string (modernc time.Time breaks SQLite date()); it is also
-- the next-due anchor used by the engine on restart.
UPDATE probe_targets
SET last_run_at = ?, last_status = ?, last_latency_ms = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ListProbeTargets :many
-- Full inventory regardless of enabled/source (the table stays small); the
-- egress-quality analyzer (#608) and the autogen sweep (#606) reason over
-- everything, unlike the engine which only ticks the enabled set.
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source
FROM probe_targets
ORDER BY id;

-- name: ListProbeTargetsByDevice :many
-- Device-bound targets for the device detail health panel (#606).
SELECT id, name, module, target, interval_seconds, timeout_seconds, enabled, notes, last_run_at, last_status, last_latency_ms, last_error, created_at, updated_at, vantage, options, device_id, source
FROM probe_targets
WHERE device_id = ?
ORDER BY id;

-- name: DetachProbeTargetsFromDevice :execrows
-- Device deletion hook (#606): unbind every bound target. Policy-generated
-- (auto) targets die with their origin; manual and system ones keep running
-- unbound. The main DB does not enable the foreign_keys pragma, so this
-- explicit sweep is the real cascade.
UPDATE probe_targets
SET device_id = NULL,
    enabled = CASE WHEN source = 'auto' THEN 0 ELSE enabled END,
    updated_at = CURRENT_TIMESTAMP
WHERE device_id = ?;
