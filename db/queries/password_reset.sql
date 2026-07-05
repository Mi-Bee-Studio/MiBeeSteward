-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (user_id, token, expires_at)
VALUES (?, ?, ?)
RETURNING *;

-- name: GetPasswordResetByToken :one
SELECT * FROM password_reset_tokens WHERE token = ?;

-- name: MarkPasswordResetUsed :exec
UPDATE password_reset_tokens
SET used_at = CURRENT_TIMESTAMP
WHERE token = ? AND used_at IS NULL;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM password_reset_tokens WHERE expires_at < CURRENT_TIMESTAMP;

-- name: ListPasswordResetTokensByUser :many
SELECT * FROM password_reset_tokens WHERE user_id = ? ORDER BY created_at DESC;
