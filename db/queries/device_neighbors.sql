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

-- name: ListDeviceNeighborsWithDevice :many
-- Like ListDeviceNeighbors, but LEFT JOINs devices on neighbor_mac so the
-- caller can show the neighbor's name/IP/type (not just its MAC) when the
-- neighbor has itself been scanned. The neighbor_* fields are NULL when the
-- neighbor device is not in the registry yet (unidentified neighbor).
SELECT
    sqlc.embed(device_neighbors),
    d.id   AS neighbor_device_id,
    d.name AS neighbor_name,
    d.ip_address AS neighbor_ip,
    d.type AS neighbor_type,
    d.status AS neighbor_status
FROM device_neighbors
LEFT JOIN devices d ON device_neighbors.neighbor_mac = d.mac_address
WHERE device_neighbors.device_id = ?
ORDER BY device_neighbors.protocol, device_neighbors.neighbor_mac;

-- name: ListAllDeviceNeighbors :many
-- Paginated admin view of all neighbor edges across all devices.
SELECT * FROM device_neighbors ORDER BY id DESC LIMIT ? OFFSET ?;

-- name: ListTopologyEdges :many
-- Every neighbor edge across all devices, JOINed to resolve the neighbor's
-- device_id (so the topology graph can draw device→device edges as solid and
-- device→unidentified-MAC edges as dashed). network_id <= 0 means all networks.
SELECT
    dn.id, dn.device_id, dn.neighbor_mac, dn.protocol, dn.local_port, dn.remote_port,
    dn.first_seen, dn.last_seen,
    d.id AS to_device_id
FROM device_neighbors dn
LEFT JOIN devices d ON dn.neighbor_mac = d.mac_address
WHERE (? <= 0 OR dn.network_id = ?)
ORDER BY dn.id;

-- name: CountDeviceNeighbors :one
SELECT COUNT(*) FROM device_neighbors;

-- name: DeleteDeviceNeighborsForDevice :execrows
DELETE FROM device_neighbors WHERE device_id = ?;
