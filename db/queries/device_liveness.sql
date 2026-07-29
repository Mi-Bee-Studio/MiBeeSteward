-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- device_liveness queries. The table physically lives in heartbeat.db (declared
-- in db/schema.sql only so sqlc can generate this code). checked_at is stored as
-- RFC3339 text (see heartbeat_store.go commitLivenessBatch), so range filters
-- use plain comparison (text-lexicographic == chronological for RFC3339) and
-- avoid SQLite date() arithmetic which is NULL on that format.

-- name: ListDeviceLiveness :many
SELECT id, device_id, status, source, checked_at
FROM device_liveness
WHERE device_id = ? AND checked_at >= ? AND checked_at <= ?
ORDER BY checked_at DESC
LIMIT ? OFFSET ?;

-- name: CountDeviceLiveness :one
SELECT COUNT(*) FROM device_liveness
WHERE device_id = ? AND checked_at >= ? AND checked_at <= ?;

-- name: GetOnlineRatio :one
SELECT
    CAST(COALESCE(CAST(SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS REAL) / COUNT(*), 0.0) AS REAL) AS online_ratio,
    CAST(COUNT(*) AS INTEGER) AS sample_count
FROM device_liveness
WHERE device_id = ? AND checked_at >= ?;

-- name: GetLastOnlineAt :one
SELECT checked_at FROM device_liveness
WHERE device_id = ? AND status = 'online'
ORDER BY checked_at DESC
LIMIT 1;

-- name: DeleteLivenessOlderThanBatched :execrows
DELETE FROM device_liveness
WHERE rowid IN (
    SELECT rowid FROM device_liveness WHERE device_liveness.checked_at < ? LIMIT ?
);

-- name: DeleteLivenessByDevice :execrows
DELETE FROM device_liveness WHERE device_id = ?;
