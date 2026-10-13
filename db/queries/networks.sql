-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateNetwork :one
INSERT INTO networks (name, cidr, site)
VALUES (?, ?, ?)
RETURNING id, name, cidr, site, agent_id, metadata, created_at, updated_at;

-- name: GetNetwork :one
SELECT id, name, cidr, site, agent_id, metadata, created_at, updated_at
FROM networks
WHERE id = ?;

-- name: GetNetworkByAgentID :one
-- Resolve the network a discovering agent is bound to (via networks.agent_id).
-- Used by the agent-command dispatch path to enforce the boundary invariant
-- (issue #19): before enqueueing a scan command we check the requested targets
-- fall inside THIS agent's network. An agent_id maps to at most one network
-- because SetNetworkAgentID is 1:1 (a token is bound to one network, and the
-- token's network gets stamped here on mint).
SELECT id, name, cidr, site, agent_id, metadata, created_at, updated_at
FROM networks
WHERE agent_id = ?
LIMIT 1;

-- name: ListNetworks :many
SELECT id, name, cidr, site, agent_id, metadata, created_at, updated_at
FROM networks
ORDER BY id;

-- name: ListNetworksWithAgentLiveness :many
-- Networks plus the owning agent's last report time (#557): the mirror-
-- freshness fact for agent/peer-managed segments. An agent-managed network
-- carries agent_tokens.last_used_at (the peer reporter is an agent too, so
-- federated mirrors get the same signal); center-local networks get NULL.
-- Dedicated query rather than extending ListNetworks: the other callers
-- (service discovery, probe dispatch, flow scoping) never need the JOIN.
SELECT n.id, n.name, n.cidr, n.site, n.agent_id, n.metadata, n.created_at, n.updated_at,
       t.last_used_at AS agent_last_used_at
FROM networks n
LEFT JOIN agent_tokens t ON t.agent_id = n.agent_id
ORDER BY n.id;

-- name: SetNetworkAgentID :exec
-- Stamp (or clear) the discovering-agent id on a network. Called by the agent-
-- token admin handler: when an admin mints a token bound to a network, the
-- network is marked agent-managed so the center's heartbeat excludes it (the
-- agent's reports ARE the liveness signal) and the lease sweeper scopes to it.
-- Passing an empty string CLEARS the agent_id (used on token revoke/delete).
-- Note: the value is a bind parameter (not a SQL literal), so this is safe from
-- the sqlc SQLite empty-string-literal truncation bug that affects heartbeat.go
-- and lease_sweeper.go (those use raw SQL for that reason).
UPDATE networks SET agent_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeleteNetwork :exec
-- Delete a logical network. All FK references are ON DELETE SET NULL or
-- CASCADE, so this is safe at the DB level.
DELETE FROM networks WHERE id = ?;

-- name: UpdateNetworkRaw
-- NOTE: this query is intentionally NOT a sqlc-managed query. sqlc v1.31.1
-- truncates the generated string for multi-bind UPDATE statements (drops the
-- trailing `?`), so UpdateNetwork is implemented with raw database/sql in
-- network.go (handler), reusing GetNetwork to read the updated row back.

