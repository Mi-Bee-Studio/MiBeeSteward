-- name: UpsertDeviceNeighbor :exec
-- Insert or refresh a neighbor edge. ON CONFLICT updates last_seen (and ports
-- if they changed) without losing first_seen. The UNIQUE(device_id, neighbor_mac,
-- protocol) constraint backs the conflict target.
INSERT INTO device_neighbors (device_id, neighbor_mac, protocol, local_port, remote_port, network_id, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(device_id, neighbor_mac, protocol) DO UPDATE SET
    local_port = CASE WHEN excluded.local_port != '' THEN excluded.local_port ELSE device_neighbors.local_port END,
    remote_port = CASE WHEN excluded.remote_port != '' THEN excluded.remote_port ELSE device_neighbors.remote_port END,
    network_id = COALESCE(excluded.network_id, device_neighbors.network_id),
    last_seen = excluded.last_seen;

-- name: ListDeviceNeighbors :many
-- All neighbors of a device (the local-end device_id), for the topology view.
SELECT * FROM device_neighbors WHERE device_id = ? ORDER BY protocol, neighbor_mac;

-- name: ListAllDeviceNeighbors :many
-- Paginated admin view of all neighbor edges across all devices.
SELECT * FROM device_neighbors ORDER BY id DESC LIMIT ? OFFSET ?;

-- name: CountDeviceNeighbors :one
SELECT COUNT(*) FROM device_neighbors;

-- name: DeleteDeviceNeighborsForDevice :execrows
DELETE FROM device_neighbors WHERE device_id = ?;
