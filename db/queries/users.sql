-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, role, failed_login_attempts, locked_until, must_change_password)
VALUES (?, ?, ?, ?, 0, NULL, ?)
RETURNING id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password;

-- name: GetUserByID :one
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password
FROM users
WHERE id = ?;

-- name: GetUserByEmail :one
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password
FROM users
WHERE email = ?;

-- name: GetUserByUsername :one
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password
FROM users
WHERE username = ?;

-- name: ListUsers :many
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password
FROM users
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpdateUser :one
UPDATE users
SET username = ?, email = ?, password_hash = ?, role = ?, failed_login_attempts = ?, locked_until = ?, must_change_password = ?, password_changed_at = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password;

-- name: DeleteUser :execrows
DELETE FROM users
WHERE id = ?;

-- name: UpdateLoginAttempts :exec
UPDATE users
SET failed_login_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ResetLoginAttempts :exec
UPDATE users
SET failed_login_attempts = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: SetMustChangePassword :exec
UPDATE users
SET must_change_password = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
