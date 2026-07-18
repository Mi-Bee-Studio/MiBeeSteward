-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateDashboardConfig :one
INSERT INTO dashboard_configs (name, type, data_source, query, refresh_interval, position)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id, name, type, data_source, query, refresh_interval, position, created_at, updated_at;

-- name: ListConfigs :many
SELECT id, name, type, data_source, query, refresh_interval, position, created_at, updated_at
FROM dashboard_configs
ORDER BY id;

-- name: UpdateDashboardConfig :one
UPDATE dashboard_configs
SET name = ?, type = ?, data_source = ?, query = ?, refresh_interval = ?, position = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, type, data_source, query, refresh_interval, position, created_at, updated_at;

-- name: DeleteDashboardConfig :execrows
DELETE FROM dashboard_configs
WHERE id = ?;
