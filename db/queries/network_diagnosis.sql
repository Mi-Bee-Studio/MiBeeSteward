-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero
-- General Public License v3.0 or later. See LICENSE for the full text. A
-- commercial license is available for use cases the AGPL does not
-- accommodate; see LICENSE-COMMERCIAL.md.

-- Read-side queries for the per-device network-anomaly diagnosis (#761).
-- The diagnosis engine is pure read: it joins the address-observation history
-- (device_sightings), the per-IP liveness facts (scan_snapshots), the
-- multi-homed presence layer (device_network_presence) and the change stream
-- (change_log) into a classified verdict with an evidence chain. No new
-- storage: every input row is written by the existing scan/report pipelines.

-- name: ListDeviceChangeHistory :many
-- Recent change-stream rows for one device (identity moves, takeovers,
-- lost/recovered). The diagnosis engine reads the identity-diff JSON to spot
-- same-IP MAC takeovers that sightings alone cannot see.
SELECT id, agent_id, network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at
FROM change_log
WHERE entity_type = 'device' AND entity_id = ?
ORDER BY detected_at DESC
LIMIT ?;

-- (FindDevicesByHostname and ListSnapshotLivenessForNetwork live as raw SQL
-- in internal/service/diagnostics: sqlc's SQLite parser truncates their
-- trailing bytes - the same documented bug that forced ListStaleAgentSnapshots
-- and the CASE-WHEN upsert to raw SQL elsewhere in this repo.)

-- name: ListDevicePresences :many
-- The multi-homed presence layer for one device (#526): every network the
-- asset is actively seen in with that network's current ip. Freshness across
-- more than one network is the dual-homed signal (vs. a genuine mover whose
-- home presence goes stale).
SELECT id, device_id, network_id, ip_address, vantage, first_seen, last_seen
FROM device_network_presence
WHERE device_id = ?
ORDER BY network_id;
