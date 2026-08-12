-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. See LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- device_configs queries: the versioned running-config store (#137). The pull
-- probe writes a row per fetch; the API/UI reads the version list (without the
-- full text) + a single version's full text on demand.

-- name: CreateDeviceConfig :one
-- Insert one fetched config snapshot. diff_from_prev is the unified diff vs the
-- prior version (computed by the caller via internal/configdiff); empty for a
-- first-ever capture.
INSERT INTO device_configs (device_id, config_hash, config_text, protocol, diff_from_prev)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: GetDeviceConfig :one
-- Full row for one version (the detail / diff view fetches config_text by id).
SELECT * FROM device_configs WHERE id = ?;

-- name: GetLatestDeviceConfig :one
-- The most recent snapshot for a device -- the baseline a new fetch diffs
-- against, and the "current config" the device detail shows.
SELECT * FROM device_configs WHERE device_id = ? ORDER BY id DESC LIMIT 1;

-- name: ListDeviceConfigs :many
-- Version history for the device-detail "Config History" tab. Omits config_text
-- (potentially large) -- the list shows metadata; the full text loads by id.
SELECT id, device_id, config_hash, protocol, diff_from_prev, fetched_at
FROM device_configs
WHERE device_id = ?
ORDER BY id DESC
LIMIT ? OFFSET ?;

-- name: CountDeviceConfigs :one
SELECT COUNT(*) FROM device_configs WHERE device_id = ?;
