-- name: CreateDeviceSystem :one
INSERT INTO device_systems (
    device_id, name, entry_url, description, category,
    metrics_url, metrics_enabled, tags
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, device_id, name, entry_url, description, category, metrics_url, metrics_enabled, tags, created_at, updated_at;

-- name: GetDeviceSystem :one
SELECT id, device_id, name, entry_url, description, category, metrics_url, metrics_enabled, tags, created_at, updated_at
FROM device_systems
WHERE id = ?;

-- name: ListDeviceSystemsByDevice :many
SELECT id, device_id, name, entry_url, description, category, metrics_url, metrics_enabled, tags, created_at, updated_at
FROM device_systems
WHERE device_id = ?
  AND (? = '' OR category = ?)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: ListAllDeviceSystems :many
SELECT id, device_id, name, entry_url, description, category, metrics_url, metrics_enabled, tags, created_at, updated_at
FROM device_systems
WHERE (? = '' OR category = ?)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpdateDeviceSystem :one
UPDATE device_systems
SET device_id = ?, name = ?, entry_url = ?, description = ?, category = ?,
    metrics_url = ?, metrics_enabled = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, device_id, name, entry_url, description, category, metrics_url, metrics_enabled, tags, created_at, updated_at;

-- name: DeleteDeviceSystem :execrows
DELETE FROM device_systems
WHERE id = ?;

-- name: CountDeviceSystemsByDevice :one
SELECT COUNT(*) AS count
FROM device_systems
WHERE device_id = ?;

-- name: ListDeviceSystemsForSD :many
SELECT ds.id, ds.device_id, ds.name, ds.entry_url, ds.description, ds.category,
       ds.metrics_url, ds.metrics_enabled, ds.tags, ds.created_at, ds.updated_at,
       d.name AS device_name, d.type AS device_type, d.location AS device_location
FROM device_systems ds
JOIN devices d ON ds.device_id = d.id
WHERE ds.metrics_enabled = 1;
