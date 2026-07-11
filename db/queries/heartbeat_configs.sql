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

-- NOTE: the agent-network exclusion (configs whose device belongs to an
-- agent-managed network should NOT be probed locally) is intentionally NOT a
-- sqlc query. sqlc's SQLite parser truncates queries whose WHERE clause
-- contains an empty-string literal ('') — see db/queries/scan_snapshots.sql
-- for the same bug. The exclusion is done via raw SQL in
-- internal/service/heartbeat.go (listLocalProbeConfigsSQL), matching the
-- device_bridge.go pattern for queries sqlc can't handle.
