-- name: CreateNotificationRule :one
INSERT INTO notification_rules (name, event_type, scope_type, scope_network_id, scope_device_uuid, channel_id, cooldown_minutes, enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListNotificationRules :many
SELECT * FROM notification_rules ORDER BY created_at DESC;

-- name: GetNotificationRule :one
SELECT * FROM notification_rules WHERE id = ?;

-- name: UpdateNotificationRule :one
UPDATE notification_rules SET name = ?, event_type = ?, scope_type = ?, scope_network_id = ?, scope_device_uuid = ?, channel_id = ?, cooldown_minutes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *;

-- name: SetNotificationRuleEnabled :one
UPDATE notification_rules SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? RETURNING *;

-- name: MarkNotificationRuleTriggered :exec
UPDATE notification_rules SET last_triggered_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeleteNotificationRule :exec
DELETE FROM notification_rules WHERE id = ?;

-- name: ListEnabledRulesByEventType :many
SELECT * FROM notification_rules WHERE enabled = 1 AND event_type = ? ORDER BY id;
