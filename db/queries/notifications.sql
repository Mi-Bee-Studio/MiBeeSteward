-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateChannel :one
INSERT INTO notification_channels (name, type, config, enabled)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: ListChannels :many
SELECT * FROM notification_channels ORDER BY created_at DESC;

-- name: GetChannelByID :one
SELECT * FROM notification_channels WHERE id = ?;

-- name: UpdateChannel :one
UPDATE notification_channels
SET name = ?, type = ?, config = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: DeleteChannel :exec
DELETE FROM notification_channels WHERE id = ?;

-- name: CreateNotificationLog :one
INSERT INTO notification_log (rule_id, channel_id, status, payload, error_message)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: ListNotificationLogs :many
SELECT * FROM notification_log ORDER BY sent_at DESC LIMIT ? OFFSET ?;

-- name: GetNotificationLogByID :one
SELECT * FROM notification_log WHERE id = ?;

-- name: ListNotificationLogsByRule :many
SELECT * FROM notification_log WHERE rule_id = ? ORDER BY sent_at DESC;

-- name: ListNotificationLogsByChannel :many
SELECT * FROM notification_log WHERE channel_id = ? ORDER BY sent_at DESC;

-- name: CountNotificationLogs :one
SELECT COUNT(*) FROM notification_log;

-- name: DeleteNotificationLogsOlderThanBatched :execrows
-- Retention sweep (batched): deletes up to ? rows older than the cutoff.
DELETE FROM notification_log
WHERE rowid IN (
    SELECT rowid FROM notification_log WHERE notification_log.sent_at < ? LIMIT ?
);
