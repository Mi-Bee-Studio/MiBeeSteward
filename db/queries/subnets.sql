-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. See LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: UpsertSubnet :exec
-- Insert or refresh a subnet observed during a scan. There is no natural UNIQUE
-- on (network_id, cidr) in the base schema, so the conflict target is a soft
-- match: the caller first checks existence then inserts/updates. This query is
-- the insert path; use UpdateSubnetLastSeen to refresh an existing row.
INSERT INTO subnets (network_id, cidr, vlan_id, gateway, metadata, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: UpdateSubnetLastSeen :execrows
-- Refresh last_seen for a subnet identified by (network_id, cidr).
UPDATE subnets SET last_seen = ?
WHERE network_id = ? AND cidr = ?;

-- name: GetSubnetByCIDR :one
-- Look up a subnet row by its (network_id, cidr) to decide insert-vs-update.
SELECT * FROM subnets WHERE network_id = ? AND cidr = ?;

-- name: ListSubnets :many
-- All subnets observed on a network. network_id <= 0 = all networks.
SELECT * FROM subnets
WHERE (? <= 0 OR network_id = ?)
ORDER BY cidr;
