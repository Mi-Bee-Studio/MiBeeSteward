-- name: CreateScanTask :one
INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, 1)
RETURNING id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at;

-- name: GetScanTask :one
SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
FROM scan_tasks
WHERE id = ?;

-- name: ListScanTasks :many
SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
FROM scan_tasks
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpdateScanTask :one
UPDATE scan_tasks
SET name = ?, targets = ?, cron_expr = ?, pipeline_config = ?, global_labels = ?,
    timeout = ?, concurrent_hosts = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at;

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
SELECT id, name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled, last_run_at, next_run_at, last_run_status, created_at, updated_at
FROM scan_tasks
WHERE enabled = 1;

-- name: CountScanTasks :one
SELECT COUNT(*)
FROM scan_tasks;
