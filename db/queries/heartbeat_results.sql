-- name: CreateResult :one
INSERT INTO heartbeat_results (device_id, config_id, status, latency_ms, error_message, checked_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, device_id, config_id, status, latency_ms, error_message, checked_at;

-- name: ListHeartbeatResultsByDevice :many
SELECT id, device_id, config_id, status, latency_ms, error_message, checked_at
FROM heartbeat_results
WHERE device_id = ?
  AND (? = '' OR checked_at >= ?)
  AND (? = '' OR checked_at <= ?)
ORDER BY checked_at DESC
LIMIT ? OFFSET ?;

-- name: DeleteOlderThan :execrows
DELETE FROM heartbeat_results
WHERE checked_at < ?;

-- name: GetLatestCheckedAt :one
SELECT checked_at FROM heartbeat_results WHERE config_id = ? ORDER BY checked_at DESC LIMIT 1;

-- name: ListHeartbeatResultsByTimeRange :many
SELECT id, device_id, config_id, status, latency_ms, error_message, checked_at
FROM heartbeat_results
WHERE device_id = ? AND checked_at >= ? AND checked_at <= ?
ORDER BY checked_at DESC
LIMIT ? OFFSET ?;

-- name: CountHeartbeatResultsByTimeRange :one
SELECT COUNT(*) FROM heartbeat_results
WHERE device_id = ? AND checked_at >= ? AND checked_at <= ?;

-- name: GetHeartbeatStats :one
SELECT
    CAST(COALESCE(AVG(latency_ms), 0.0) AS REAL) as avg_latency_ms,
    CAST(COALESCE(SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END), 0) AS INTEGER) as success_count,
    CAST(COALESCE(SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END), 0) AS INTEGER) as fail_count,
    CAST(COALESCE(SUM(CASE WHEN status = 'timeout' THEN 1 ELSE 0 END), 0) AS INTEGER) as timeout_count
FROM heartbeat_results
WHERE device_id = ? AND checked_at >= ? AND checked_at <= ?;
