-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

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
-- Columns listed explicitly: sqlc v1.27.0's sqlc.embed() corrupts sibling
-- query generation, so it is avoided here.
SELECT
    device_neighbors.id AS id,
    device_neighbors.device_id AS device_id,
    device_neighbors.neighbor_mac AS neighbor_mac,
    device_neighbors.protocol AS protocol,
    device_neighbors.local_port AS local_port,
    device_neighbors.remote_port AS remote_port,
    device_neighbors.first_seen AS first_seen,
    device_neighbors.last_seen AS last_seen,
    d.id   AS resolved_device_id,
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
-- device_id (so the topology graph can draw device-to-device edges as solid and
-- device-to-unidentified-MAC edges as dashed). network_id <= 0 means all networks.
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

-- name: DeleteDeviceNeighborsOlderThanBatched :execrows
-- Retention sweep (batched) for device_neighbors. Removes edges whose
-- last_seen is older than the cutoff, in batches to avoid holding the write
-- lock on large tables (mirrors the other retention deletes).
DELETE FROM device_neighbors
WHERE id IN (
    SELECT sub.id FROM device_neighbors AS sub WHERE sub.last_seen < ? LIMIT ?
);

-- name: DeleteDeviceNeighborsForDevice :execrows
DELETE FROM device_neighbors WHERE device_id = ?;
