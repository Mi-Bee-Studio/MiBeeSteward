-- name: CreateHeartbeatConfig :one
INSERT INTO heartbeat_configs (device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled, created_at, updated_at;

-- name: GetHeartbeatConfig :one
SELECT id, device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled, created_at, updated_at
FROM heartbeat_configs
WHERE id = ?;

-- name: ListHeartbeatConfigsByDevice :many
SELECT id, device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled, created_at, updated_at
FROM heartbeat_configs
WHERE device_id = ?;

-- name: UpdateHeartbeatConfig :one
UPDATE heartbeat_configs
SET method = ?, target = ?, interval_seconds = ?, timeout_seconds = ?,
    snmp_community = ?, snmp_oid = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled, created_at, updated_at;

-- name: DeleteHeartbeatConfig :execrows
DELETE FROM heartbeat_configs
WHERE id = ?;

-- name: ListEnabledConfigs :many
SELECT id, device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled, created_at, updated_at
FROM heartbeat_configs
WHERE enabled = 1;
