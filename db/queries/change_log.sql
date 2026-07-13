-- name: CreateChangeLog :one
INSERT INTO change_log (agent_id, network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListChangeLog :many
SELECT id, agent_id, network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at
FROM change_log
WHERE (? = 0 OR network_id = ?)
  AND (? = '' OR change_type = ?)
  AND (? = '' OR entity_type = ?)
ORDER BY detected_at DESC
LIMIT ? OFFSET ?;

-- name: CountChangeLog :one
SELECT COUNT(*)
FROM change_log
WHERE (? = 0 OR network_id = ?)
  AND (? = '' OR change_type = ?)
  AND (? = '' OR entity_type = ?);

-- name: DeleteChangeLogOlderThanBatched :execrows
-- Retention sweep. Deletes rows older than the cutoff in batches to avoid
-- holding the write lock on large tables (mirrors the other retention deletes).
DELETE FROM change_log
WHERE id IN (
    SELECT sub.id FROM change_log AS sub WHERE sub.detected_at < ? LIMIT ?
);
