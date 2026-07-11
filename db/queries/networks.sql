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
