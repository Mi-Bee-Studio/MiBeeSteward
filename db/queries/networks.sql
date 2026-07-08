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
