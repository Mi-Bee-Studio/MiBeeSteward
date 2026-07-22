-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. See LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: UpsertVLAN :one
-- Insert a VLAN or refresh its last_seen. The UNIQUE(vlan_tag, network_id)
-- constraint backs the conflict target. Returns the row so the caller can
-- resolve the id when inserting a linked subnet.
INSERT INTO vlans (vlan_tag, name, description, network_id, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(vlan_tag, network_id) DO UPDATE SET
    name        = CASE WHEN excluded.name != '' THEN excluded.name ELSE vlans.name END,
    description = CASE WHEN excluded.description != '' THEN excluded.description ELSE vlans.description END,
    last_seen   = excluded.last_seen
RETURNING *;

-- name: ListVLANs :many
-- All VLANs observed on a network. network_id <= 0 = all networks.
SELECT * FROM vlans
WHERE (? <= 0 OR network_id = ?)
ORDER BY vlan_tag;
