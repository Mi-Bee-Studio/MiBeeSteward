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

-- name: SetChannelEnabled :one
-- Single-field UPDATE for the dedicated PATCH /channels/{id} toggle endpoint.
-- Writing only `enabled` (not the full row) makes the intent explicit and
-- avoids any GET-then-write race on name/type/config. See service.SetChannelEnabled.
UPDATE notification_channels
SET enabled = ?, updated_at = CURRENT_TIMESTAMP
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

-- name: ListNotificationLogsForUser :many
-- Recent notification logs with a per-user is_read flag (drives the bell's
-- unread styling).notification_log is system-wide; read state is per-user.
SELECT l.id, l.rule_id, l.channel_id, l.status, l.payload, l.error_message, l.sent_at,
       EXISTS(
           SELECT 1 FROM notification_read_states s
           WHERE s.user_id = ? AND s.notification_log_id = l.id
       ) AS is_read
FROM notification_log l
ORDER BY l.sent_at DESC
LIMIT ? OFFSET ?;

-- name: CountUnreadNotificationLogsForUser :one
-- Unread count for a user (logs with no matching read_state row).
SELECT COUNT(*) FROM notification_log l
WHERE NOT EXISTS(
    SELECT 1 FROM notification_read_states s
    WHERE s.user_id = ? AND s.notification_log_id = l.id
);

-- name: MarkAllNotificationLogsRead :execrows
-- Idempotently mark all currently-unread notification logs as read for a
-- user (INSERT OR IGNORE skips any pair already present). Returns the number
-- of rows inserted (i.e. newly-read logs).
INSERT OR IGNORE INTO notification_read_states (user_id, notification_log_id)
SELECT ?, l.id FROM notification_log l
WHERE NOT EXISTS(
    SELECT 1 FROM notification_read_states s
    WHERE s.user_id = ? AND s.notification_log_id = l.id
);
