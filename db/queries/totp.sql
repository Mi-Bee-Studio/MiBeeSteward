-- name: SetTOTPSecret :one
INSERT INTO user_totp (user_id, secret, backup_codes)
VALUES (?, ?, ?)
ON CONFLICT(user_id) DO UPDATE SET
    secret = excluded.secret,
    backup_codes = excluded.backup_codes,
    verified = 0,
    enabled = 0,
    updated_at = CURRENT_TIMESTAMP
RETURNING *;

-- name: GetTOTPByUserID :one
SELECT * FROM user_totp WHERE user_id = ?;

-- name: UpdateTOTPVerified :one
UPDATE user_totp
SET verified = ?, updated_at = CURRENT_TIMESTAMP
WHERE user_id = ?
RETURNING *;

-- name: UpdateTOTPEnabled :one
UPDATE user_totp
SET enabled = ?, updated_at = CURRENT_TIMESTAMP
WHERE user_id = ?
RETURNING *;

-- name: DeleteTOTP :exec
DELETE FROM user_totp WHERE user_id = ?;

-- name: ConsumeBackupCode :one
UPDATE user_totp
SET backup_codes = ?
WHERE user_id = ?
RETURNING *;
