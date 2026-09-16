-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, role, failed_login_attempts, locked_until, must_change_password)
VALUES (?, ?, ?, ?, 0, NULL, ?)
RETURNING id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password, token_version;

-- name: GetUserByID :one
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password, token_version
FROM users
WHERE id = ?;

-- name: GetUserByEmail :one
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password, token_version
FROM users
WHERE email = ?;

-- name: GetUserByUsername :one
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password, token_version
FROM users
WHERE username = ?;

-- name: ListUsers :many
-- Search is a substring match across username/email (case-insensitive). The
-- sentinel pattern (? = '' OR ...) means an empty search returns all rows.
-- INSTR(lower(...), lower(?)) is used because sqlc's SQLite parser rejects
-- `LIKE ? ESCAPE '\' (see scan_tasks.sql for the same pattern).
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password, token_version
FROM users
WHERE (? = '' OR INSTR(lower(username), lower(?)) > 0 OR INSTR(lower(email), lower(?)) > 0)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountUsers :one
-- Mirrors the ListUsers WHERE so the page total reflects the active search
-- (previously Total was len(page) = page size, which broke pagination counts).
SELECT COUNT(*) FROM users
WHERE (? = '' OR INSTR(lower(username), lower(?)) > 0 OR INSTR(lower(email), lower(?)) > 0);

-- name: UpdateUser :one
UPDATE users
SET username = ?, email = ?, password_hash = ?, role = ?, failed_login_attempts = ?, locked_until = ?, must_change_password = ?, password_changed_at = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password, token_version;

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

-- name: GetUserPendingSetup :one
-- The bootstrap admin seeded with an empty password hash: first-run state
-- before the operator completes the browser setup flow (POST /auth/setup).
-- At most one can exist, because the seeder only creates the admin this way.
-- The empty string is a bound param rather than a literal because sqlc's
-- SQLite rewriter elides empty-string literals and mangles LIMIT clauses.
SELECT id, username, email, password_hash, role, created_at, updated_at, failed_login_attempts, locked_until, password_changed_at, must_change_password, token_version
FROM users
WHERE password_hash = ?;


-- name: GetUserTokenVersion :one
SELECT token_version FROM users WHERE id = ?;

-- name: BumpUserTokenVersion :execrows
UPDATE users
SET token_version = token_version + 1, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
