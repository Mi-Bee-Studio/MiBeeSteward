-- name: CreateDashboardConfig :one
INSERT INTO dashboard_configs (name, type, data_source, query, refresh_interval, position)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, name, type, data_source, query, refresh_interval, position, created_at, updated_at;

-- name: ListConfigs :many
SELECT id, name, type, data_source, query, refresh_interval, position, created_at, updated_at
FROM dashboard_configs
ORDER BY id;

-- name: UpdateDashboardConfig :one
UPDATE dashboard_configs
SET name = ?, type = ?, data_source = ?, query = ?, refresh_interval = ?, position = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, type, data_source, query, refresh_interval, position, created_at, updated_at;

-- name: DeleteDashboardConfig :execrows
DELETE FROM dashboard_configs
WHERE id = ?;
