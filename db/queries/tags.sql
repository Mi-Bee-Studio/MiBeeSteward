-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later; see LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- Tag dictionary + device-tag association (#665). Built-ins (internal /
-- external / temporary / pending) are seeded idempotently at startup by the
-- tag service; they cannot be deleted (DeleteTag guards in SQL), but their
-- display name / color / description / order stay editable.

-- name: ListTags :many
SELECT id, key, name, color, description, builtin, sort_order, created_at, updated_at
FROM tags
ORDER BY builtin DESC, sort_order ASC, id ASC;

-- name: GetTag :one
SELECT id, key, name, color, description, builtin, sort_order, created_at, updated_at
FROM tags WHERE id = ?;

-- name: GetTagByKey :one
SELECT id, key, name, color, description, builtin, sort_order, created_at, updated_at
FROM tags WHERE key = ?;

-- name: CreateTag :one
INSERT INTO tags (key, name, color, description, sort_order)
VALUES (?, ?, ?, ?, ?)
RETURNING id, key, name, color, description, builtin, sort_order, created_at, updated_at;

-- name: UpdateTag :one
UPDATE tags
SET name = ?, color = ?, description = ?, sort_order = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, key, name, color, description, builtin, sort_order, created_at, updated_at;

-- name: DeleteTag :execrows
DELETE FROM tags WHERE id = ? AND builtin = 0;

-- Seed a built-in tag; no-op when the key already exists (idempotent startup).
-- name: SeedBuiltinTag :execrows
INSERT INTO tags (key, name, builtin, sort_order)
SELECT ?, ?, 1, ?
WHERE NOT EXISTS (SELECT 1 FROM tags seeded WHERE seeded.key = ?);

-- name: AddDeviceTag :execrows
INSERT INTO device_tags (device_id, tag_id) VALUES (?, ?)
ON CONFLICT (device_id, tag_id) DO NOTHING;

-- name: RemoveDeviceTag :execrows
DELETE FROM device_tags WHERE device_id = ? AND tag_id = ?;

-- name: ClearDeviceTags :exec
DELETE FROM device_tags WHERE device_id = ?;

-- name: ListDeviceTags :many
SELECT t.id, t.key, t.name, t.color, t.builtin
FROM tags t
JOIN device_tags dt ON dt.tag_id = t.id
WHERE dt.device_id = ?
ORDER BY t.sort_order ASC, t.id ASC;

-- Batched variant for the list view (one query per page, not per row).
-- name: ListTagAssignments :many
SELECT dt.device_id, t.id, t.key, t.name, t.color, t.builtin
FROM device_tags dt
JOIN tags t ON t.id = dt.tag_id
WHERE dt.device_id IN (sqlc.slice('device_ids'))
ORDER BY t.sort_order ASC, t.id ASC;
