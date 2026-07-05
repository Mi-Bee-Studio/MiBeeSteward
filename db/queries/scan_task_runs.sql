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
