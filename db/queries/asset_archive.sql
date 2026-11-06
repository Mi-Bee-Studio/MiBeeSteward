-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later; see LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- Asset-archive lifecycle engine (#663). Time comparisons deliberately happen
-- in GO, not in SQL: offline_since / online_since are written by several
-- engines with mixed TEXT serialization shapes (modernc time.Time vs
-- RFC3339Nano strings), so string ordering in SQL is unreliable. The engine
-- selects candidate rows and applies thresholds in Go, then writes by id.

-- name: InsertArchiveEvent :exec
INSERT INTO asset_archive_events (device_id, event, triggered_by, detail, occurred_at)
VALUES (?, ?, ?, ?, ?);

-- name: ArchiveDevice :execrows
UPDATE devices
SET archived_at = ?, online_since = NULL, updated_at = ?
WHERE id = ? AND archived_at IS NULL;

-- name: StampArchivedOnlineSince :execrows
UPDATE devices
SET online_since = ?, updated_at = ?
WHERE archived_at IS NOT NULL AND status = 'online' AND online_since IS NULL;

-- name: ListArchivedOnline :many
SELECT id, archive_pin, online_since
FROM devices
WHERE archived_at IS NOT NULL AND status = 'online' AND online_since IS NOT NULL;

-- name: ListArchivedOnlineBroken :many
SELECT id, online_since
FROM devices
WHERE archived_at IS NOT NULL AND status = 'offline' AND online_since IS NOT NULL;

-- name: RestoreArchivedDevice :execrows
UPDATE devices
SET archived_at = NULL, online_since = NULL, updated_at = ?
WHERE id = ? AND archived_at IS NOT NULL;

-- name: ClearOnlineSince :execrows
UPDATE devices SET online_since = NULL, updated_at = ? WHERE id = ?;

-- name: SetDeviceArchivePin :execrows
UPDATE devices SET archive_pin = ?, updated_at = ? WHERE id = ?;

-- === Periodic-pattern learner (#664) ===

-- Candidate select gains the periodic flag so the exemption check needs no
-- second round-trip.
-- name: ListAutoArchiveCandidates :many
SELECT id, name, mac_address, ip_address, offline_since, periodic,
       COALESCE(archive_offline_days_override, 0) AS offline_days_override
FROM devices
WHERE archived_at IS NULL
  AND archive_pin != 'force_active'
  AND scan_source = 'scanner_v2'
  AND status = 'offline'
  AND offline_since IS NOT NULL;

-- Learning input: the device's lifecycle event series, oldest first. The
-- learner filters event/trigger values in Go (small per-device series).
-- name: ListDeviceArchiveEvents :many
SELECT id, event, triggered_by, occurred_at
FROM asset_archive_events
WHERE device_id = ?
ORDER BY occurred_at ASC, id ASC;

-- Archived devices are re-evaluated every tick: a recognized pattern both
-- flags the device periodic AND auto-restores it out of the archive. The
-- threshold override rides along: the exemption only applies below the
-- max_threshold_days cap, evaluated per device.
-- name: ListArchivedDeviceOverrides :many
SELECT id, COALESCE(archive_offline_days_override, 0) AS offline_days_override
FROM devices WHERE archived_at IS NOT NULL;

-- Periodic devices are checked for pattern expiry (absent > 2x cycle).
-- name: ListPeriodicDeviceStates :many
SELECT id, status, periodic_cycle_days FROM devices WHERE periodic = 1;

-- name: SetDevicePeriodic :execrows
UPDATE devices SET periodic = ?, periodic_cycle_days = ?, updated_at = ?
WHERE id = ?;

-- === Archive API surface (#666) ===

-- name: UpdateArchiveThresholdOverride :execrows
UPDATE devices SET archive_offline_days_override = ?, updated_at = ? WHERE id = ?;

-- Archive list view (#667): archived rows newest-first with the network
-- label and the fields the list/dossier UI badges on.
-- name: ListArchivedDevices :many
SELECT d.id, d.name, d.type, d.brand, d.model, d.ip_address, d.mac_address,
       d.status, d.archived_at, d.archive_pin, d.online_since, d.offline_since,
       d.periodic, d.periodic_cycle_days, d.scan_source,
       d.network_id, n.name AS network_name,
       d.created_at, d.updated_at
FROM devices d
LEFT JOIN networks n ON n.id = d.network_id
WHERE d.archived_at IS NOT NULL
ORDER BY d.archived_at DESC
LIMIT ? OFFSET ?;

-- name: CountArchivedDevices :one
SELECT COUNT(*) FROM devices WHERE archived_at IS NOT NULL;

-- Dossier material (#666): change_log rows for THIS device (the shared
-- ListChangeLog has no entity_id filter).
-- name: ListDeviceChangeEvents :many
SELECT id, change_type, before_data, after_data, detected_at
FROM change_log
WHERE entity_type = 'device' AND entity_id = ?
ORDER BY detected_at DESC
LIMIT ?;
