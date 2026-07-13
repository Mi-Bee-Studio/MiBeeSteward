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
