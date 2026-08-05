-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateScanTask :one
INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
RETURNING id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at;

-- name: GetScanTask :one
SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
FROM scan_tasks
WHERE id = ?;

-- name: ListScanTasks :many
SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
FROM scan_tasks
ORDER BY id
LIMIT ? OFFSET ?;

-- name: ListScanTasksSearch :many
-- Optional case-insensitive substring search over name + targets. The first
-- param is the raw search term; when it is '' the (? = '') short-circuits to
-- TRUE so this behaves like ListScanTasks (no filter). INSTR() is used instead
-- of LIKE so the search term needs no escaping (literal %/_ are not wildcards)
-- and we pass the same value to both columns + the empty-check.
-- CountScanTasksSearch below MUST use the same WHERE clause so totals match.
SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
FROM scan_tasks
WHERE (? = '' OR INSTR(lower(name), lower(?)) > 0 OR INSTR(lower(targets), lower(?)) > 0)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpdateScanTask :one
UPDATE scan_tasks
SET name = ?, targets = ?, cron_expr = ?, pipeline_config = ?, global_labels = ?,
    timeout = ?, concurrent_hosts = ?, credential_id = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at;

-- name: DeleteScanTask :execrows
DELETE FROM scan_tasks
WHERE id = ?;

-- name: UpdateScanTaskStatus :exec
UPDATE scan_tasks
SET last_run_at = ?, next_run_at = ?, last_run_status = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ToggleScanTaskEnabled :exec
UPDATE scan_tasks
SET enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ListEnabledScanTasks :many
SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, credential_id, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
FROM scan_tasks
WHERE enabled = 1;

-- name: CountScanTasks :one
SELECT COUNT(*)
FROM scan_tasks;

-- name: CountScanTasksSearch :one
-- Mirrors ListScanTasksSearch's WHERE clause so the pagination total reflects
-- the active search (not the unfiltered row count).
SELECT COUNT(*)
FROM scan_tasks
WHERE (? = '' OR INSTR(lower(name), lower(?)) > 0 OR INSTR(lower(targets), lower(?)) > 0);
