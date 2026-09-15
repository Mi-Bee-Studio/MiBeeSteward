-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. See LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: GetSetting :one
SELECT key, value, updated_at FROM system_settings WHERE key = ?;

-- name: ListSettings :many
SELECT key, value, updated_at FROM system_settings ORDER BY key;

-- name: UpsertSetting :exec
INSERT INTO system_settings (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP;

-- name: DeleteSetting :execrows
DELETE FROM system_settings WHERE key = ?;
