-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: SetTOTPSecret :one
INSERT INTO user_totp (user_id, secret, backup_codes)
VALUES (?, ?, ?)
ON CONFLICT(user_id) DO UPDATE SET
    secret = excluded.secret,
    backup_codes = excluded.backup_codes,
    verified = 0,
    enabled = 0,
    updated_at = CURRENT_TIMESTAMP
RETURNING *;

-- name: GetTOTPByUserID :one
SELECT * FROM user_totp WHERE user_id = ?;

-- name: UpdateTOTPVerified :one
UPDATE user_totp
SET verified = ?, updated_at = CURRENT_TIMESTAMP
WHERE user_id = ?
RETURNING *;

-- name: UpdateTOTPEnabled :one
UPDATE user_totp
SET enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE user_id = ?
RETURNING *;

-- name: DeleteTOTP :exec
DELETE FROM user_totp WHERE user_id = ?;

-- name: ConsumeBackupCode :one
UPDATE user_totp
SET backup_codes = ?
WHERE user_id = ?
RETURNING *;
