-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateScanTaskRun :one
INSERT INTO scan_task_runs (task_id, status, total_hosts, alive_hosts, new_hosts, updated_hosts, duration_ms, error_message, started_at)
VALUES (?, 'running', 0, 0, 0, 0, 0, '', ?)
RETURNING *;

-- name: UpdateScanTaskRun :exec
UPDATE scan_task_runs
SET status = ?, total_hosts = ?, alive_hosts = ?, new_hosts = ?, updated_hosts = ?,
    duration_ms = ?, error_message = ?, finished_at = ?
WHERE id = ?;

-- name: ListScanTaskRuns :many
SELECT id, task_id, status, total_hosts, alive_hosts, new_hosts, updated_hosts, duration_ms, error_message, started_at, finished_at, created_at
FROM scan_task_runs
WHERE (? = 0 OR task_id = ?)
ORDER BY id DESC
LIMIT ? OFFSET ?;

-- name: GetLatestRun :one
SELECT id, task_id, status, total_hosts, alive_hosts, new_hosts, updated_hosts, duration_ms, error_message, started_at, finished_at, created_at
FROM scan_task_runs
WHERE task_id = ?
ORDER BY id DESC
LIMIT 1;

-- name: CountScanTaskRuns :one
SELECT COUNT(*)
FROM scan_task_runs
WHERE (? = 0 OR task_id = ?);

-- name: GetScanTaskRun :one
SELECT id, task_id, status, total_hosts, alive_hosts, new_hosts, updated_hosts, duration_ms, error_message, started_at, finished_at, created_at
FROM scan_task_runs
WHERE id = ?;

-- name: DeleteScanTaskRunsOlderThanBatched :execrows
-- Retention sweep (batched): deletes up to ? runs older than the cutoff.
DELETE FROM scan_task_runs
WHERE rowid IN (
    SELECT rowid FROM scan_task_runs WHERE scan_task_runs.created_at < ? LIMIT ?
);
