-- name: ListAuditLogs :many
SELECT id, user_id, action, resource_type, resource_id, ip_address, user_agent, details, created_at
FROM audit_logs
WHERE (? = 0 OR user_id = ?)
  AND (? = '' OR action = ?)
  AND (? = '' OR resource_type = ?)
  AND (? = '' OR created_at >= ?)
  AND (? = '' OR created_at <= ?)
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: CountAuditLogs :one
SELECT COUNT(*) FROM audit_logs
WHERE (? = 0 OR user_id = ?)
  AND (? = '' OR action = ?)
  AND (? = '' OR resource_type = ?)
  AND (? = '' OR created_at >= ?)
  AND (? = '' OR created_at <= ?);
