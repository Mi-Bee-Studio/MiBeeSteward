-- name: CreateChannel :one
INSERT INTO notification_channels (name, type, config, enabled)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: ListChannels :many
SELECT * FROM notification_channels ORDER BY created_at DESC;

-- name: GetChannelByID :one
SELECT * FROM notification_channels WHERE id = ?;

-- name: UpdateChannel :one
UPDATE notification_channels
SET name = ?, type = ?, config = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: DeleteChannel :exec
DELETE FROM notification_channels WHERE id = ?;

-- name: CreateAlertRule :one
INSERT INTO alert_rules (name, device_id, condition_type, threshold, channel_id, enabled, cooldown_seconds)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListAlertRules :many
SELECT * FROM alert_rules ORDER BY created_at DESC;

-- name: GetAlertRuleByID :one
SELECT * FROM alert_rules WHERE id = ?;

-- name: UpdateAlertRule :one
UPDATE alert_rules
SET name = ?, device_id = ?, condition_type = ?, threshold = ?, channel_id = ?,
    enabled = ?, cooldown_seconds = ?, last_triggered_at = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: DeleteAlertRule :exec
DELETE FROM alert_rules WHERE id = ?;

-- name: ListAlertRulesByDevice :many
SELECT * FROM alert_rules WHERE device_id = ? ORDER BY created_at DESC;

-- name: ListEnabledAlertRules :many
SELECT * FROM alert_rules WHERE enabled = 1 ORDER BY created_at DESC;

-- name: CreateNotificationLog :one
INSERT INTO notification_log (rule_id, channel_id, status, payload, error_message)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: ListNotificationLogs :many
SELECT * FROM notification_log ORDER BY sent_at DESC LIMIT ? OFFSET ?;

-- name: GetNotificationLogByID :one
SELECT * FROM notification_log WHERE id = ?;

-- name: ListNotificationLogsByRule :many
SELECT * FROM notification_log WHERE rule_id = ? ORDER BY sent_at DESC;

-- name: ListNotificationLogsByChannel :many
SELECT * FROM notification_log WHERE channel_id = ? ORDER BY sent_at DESC;

-- name: CountNotificationLogs :one
SELECT COUNT(*) FROM notification_log;
