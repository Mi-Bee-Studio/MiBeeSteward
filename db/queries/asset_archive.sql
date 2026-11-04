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

-- name: ListAutoArchiveCandidates :many
SELECT id, name, mac_address, ip_address, offline_since,
       COALESCE(archive_offline_days_override, 0) AS offline_days_override
FROM devices
WHERE archived_at IS NULL
  AND archive_pin != 'force_active'
  AND scan_source = 'scanner_v2'
  AND status = 'offline'
  AND offline_since IS NOT NULL;

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
