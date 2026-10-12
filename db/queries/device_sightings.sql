-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero
-- General Public License v3.0 or later. See LICENSE for the full text. A
-- commercial license is available for use cases the AGPL does not
-- accommodate; see LICENSE-COMMERCIAL.md.

-- name: ListDeviceSightings :many
-- Address-observation history for one device (#527/#529), newest first.
-- Empty vantage filter returns every stream (center-local + all agents).
SELECT id, device_id, ip_address, mac_address,
       CAST(COALESCE(network_id, 0) AS INTEGER) AS network_id,
       vantage, source, first_seen, last_seen, see_count
FROM device_sightings
WHERE device_id = ? AND (? = '' OR vantage = ?)
ORDER BY last_seen DESC
LIMIT ?;

-- name: ListAllNetworkPresences :many
-- Every (device, network) presence row (#526), for the topology graph's
-- multi-homed nodes: one bulk fetch, the handler groups by device.
SELECT device_id, network_id, ip_address, vantage, first_seen, last_seen
FROM device_network_presence
ORDER BY device_id, network_id;

-- name: ListDeviceInterfaces :many
-- The device's interface census (#529): one row per ifIndex, freshest walk
-- wins (vanished ports keep their frozen last_seen row - history, not deletion).
SELECT id, device_id, if_index, if_name, if_descr, mac_address, ip_address, speed,
       first_seen, last_seen
FROM device_interfaces
WHERE device_id = ?
ORDER BY if_index;
