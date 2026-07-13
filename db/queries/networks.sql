-- name: CreateNetwork :one
INSERT INTO networks (name, cidr, site)
VALUES (?, ?, ?)
RETURNING id, name, cidr, site, agent_id, metadata, created_at, updated_at;

-- name: GetNetwork :one
SELECT id, name, cidr, site, agent_id, metadata, created_at, updated_at
FROM networks
WHERE id = ?;

-- name: ListNetworks :many
SELECT id, name, cidr, site, agent_id, metadata, created_at, updated_at
FROM networks
ORDER BY id;

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

