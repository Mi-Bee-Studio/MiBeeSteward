-- name: CreateAgentCommand :one
-- Center enqueues a command for an agent. status=pending until the agent polls.
INSERT INTO agent_commands (agent_id, command, payload)
VALUES (?, ?, ?)
RETURNING *;

-- name: ListPendingAgentCommands :many
-- Agent polls its pending commands (status=pending), oldest first.
SELECT * FROM agent_commands
WHERE agent_id = ? AND status = 'pending'
ORDER BY id
LIMIT ?;

-- name: AckAgentCommand :exec
-- Agent marks a command acknowledged (picking it up for execution).
UPDATE agent_commands SET status = 'acknowledged', acknowledged_at = CURRENT_TIMESTAMP
WHERE id = ? AND status = 'pending';

-- name: CompleteAgentCommand :exec
-- Agent reports the result of a completed command.
UPDATE agent_commands SET status = ?, result = ?
WHERE id = ?;

-- name: ListAllAgentCommands :many
-- Admin view: all commands across all agents (for the management UI).
SELECT * FROM agent_commands
ORDER BY id DESC
LIMIT ? OFFSET ?;

-- name: CountAgentCommands :one
SELECT COUNT(*) FROM agent_commands;

-- name: DeleteAgentCommand :execrows
DELETE FROM agent_commands WHERE id = ?;
