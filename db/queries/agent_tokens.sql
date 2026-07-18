-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateAgentToken :one
INSERT INTO agent_tokens (agent_id, token_hash, network_id, name)
VALUES (?, ?, ?, ?)
RETURNING id, agent_id, token_hash, network_id, name, created_at, last_used_at, revoked_at;

-- name: GetAgentTokenByHash :one
-- Look up a token by its hash for auth verification. Returns the row even when
-- revoked so the middleware can distinguish "no such token" (401) from
-- "revoked" (401 with a clearer message); the revoked_at check is in middleware.
SELECT id, agent_id, token_hash, network_id, name, created_at, last_used_at, revoked_at
FROM agent_tokens
WHERE token_hash = ?;

-- name: GetAgentToken :one
SELECT id, agent_id, token_hash, network_id, name, created_at, last_used_at, revoked_at
FROM agent_tokens
WHERE id = ?;

-- name: ListAgentTokens :many
SELECT id, agent_id, token_hash, network_id, name, created_at, last_used_at, revoked_at
FROM agent_tokens
ORDER BY id;

-- name: TouchAgentTokenLastUsed :exec
UPDATE agent_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: RevokeAgentToken :execrows
UPDATE agent_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL;

-- name: DeleteAgentToken :execrows
DELETE FROM agent_tokens WHERE id = ?;
