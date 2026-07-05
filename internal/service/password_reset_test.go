package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"

	_ "modernc.org/sqlite"
)

// setupPasswordResetTest creates an in-memory SQLite DB with users and password_reset_tokens
// tables, inserts a test user, and returns a PasswordResetService and test dependencies.
func setupPasswordResetTest(t *testing.T) (*PasswordResetService, *sql.DB, int64) {
	t.Helper()

	dbConn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })

	// Create users table
	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			failed_login_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until DATETIME,
			must_change_password BOOLEAN NOT NULL DEFAULT 0,
			password_changed_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// Create password_reset_tokens table
	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS password_reset_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token TEXT UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	require.NoError(t, err)

	queries := db.New(dbConn)

	// Create a test user
	hash, err := bcrypt.GenerateFromPassword([]byte("OldPass@2026"), bcrypt.DefaultCost)
	require.NoError(t, err)

	result, err := dbConn.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"resetuser", "reset@example.com", string(hash), "user",
	)
	require.NoError(t, err)

	userID, err := result.LastInsertId()
	require.NoError(t, err)

	svc := NewPasswordResetService(queries, nil, nil, nil)
	return svc, dbConn, userID
}

// TestRequestReset_NonExistentEmail verifies that requesting reset for a non-existent
// email returns nil (no user enumeration).
func TestRequestReset_NonExistentEmail(t *testing.T) {
	svc, dbConn, _ := setupPasswordResetTest(t)
	defer dbConn.Close()

	err := svc.RequestReset(context.Background(), "nonexistent@example.com")
	require.NoError(t, err, "should return nil for non-existent email")
}

// TestRequestReset_CreatesToken verifies that requesting reset for an existing
// user creates a valid token in the database.
func TestRequestReset_CreatesToken(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	err := svc.RequestReset(context.Background(), "reset@example.com")
	require.NoError(t, err)

	// Verify token was created
	tokens, err := queries.ListPasswordResetTokensByUser(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, tokens, 1)

	token := tokens[0]
	require.NotEmpty(t, token.Token)
	require.Equal(t, userID, token.UserID)
	require.Nil(t, token.UsedAt)
	require.True(t, token.ExpiresAt.After(time.Now()))
}

// TestValidateToken_Valid verifies that a valid token passes validation.
func TestValidateToken_Valid(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	// Create token directly
	resetToken, err := queries.CreatePasswordResetToken(context.Background(), db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     "valid-token-hex-string-64-chars-long-enough-for-testing",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	err = svc.ValidateToken(context.Background(), resetToken.Token)
	require.NoError(t, err)
}

// TestValidateToken_Expired verifies that an expired token is rejected.
func TestValidateToken_Expired(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	// Create expired token
	resetToken, err := queries.CreatePasswordResetToken(context.Background(), db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     "expired-token-hex-string-64-chars-long-enough-for-testing",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	require.NoError(t, err)

	err = svc.ValidateToken(context.Background(), resetToken.Token)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrResetTokenExpired)
}

// TestValidateToken_Used verifies that a used token is rejected.
func TestValidateToken_Used(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	resetToken, err := queries.CreatePasswordResetToken(context.Background(), db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     "used-token-hex-string-64-chars-long-enough-for-testing",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Mark as used
	err = queries.MarkPasswordResetUsed(context.Background(), resetToken.Token)
	require.NoError(t, err)

	err = svc.ValidateToken(context.Background(), resetToken.Token)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrResetTokenUsed)
}

// TestValidateToken_NonExistent verifies that a non-existent token is rejected.
func TestValidateToken_NonExistent(t *testing.T) {
	svc, _, _ := setupPasswordResetTest(t)

	err := svc.ValidateToken(context.Background(), "nonexistent-token")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrResetTokenInvalid)
}

// TestResetPassword_Success verifies the full password reset flow:
// request → validate → reset → verify old password no longer works.
func TestResetPassword_Success(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	// Create a token
	resetToken, err := queries.CreatePasswordResetToken(context.Background(), db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     "full-flow-token-hex-string-64-chars-long-enough-testing",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Validate token first
	err = svc.ValidateToken(context.Background(), resetToken.Token)
	require.NoError(t, err)

	// Reset password
	newPassword := "NewStrong@Pass1"
	err = svc.ResetPassword(context.Background(), resetToken.Token, newPassword)
	require.NoError(t, err)

	// Verify old password no longer works
	user, err := queries.GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("OldPass@2026"))
	require.Error(t, err, "old password should no longer work")

	// Verify new password works
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(newPassword))
	require.NoError(t, err, "new password should work")

	// Verify token is now used
	usedToken, err := queries.GetPasswordResetByToken(context.Background(), resetToken.Token)
	require.NoError(t, err)
	require.NotNil(t, usedToken.UsedAt)
}

// TestResetPassword_ExpiredToken verifies that expired tokens are rejected.
func TestResetPassword_ExpiredToken(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	resetToken, err := queries.CreatePasswordResetToken(context.Background(), db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     "expired-reset-token-hex-string-64-chars-long-enough",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	require.NoError(t, err)

	err = svc.ResetPassword(context.Background(), resetToken.Token, "NewPass@2026")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrResetTokenExpired)
}

// TestResetPassword_UsedToken verifies that used tokens cannot be reused.
func TestResetPassword_UsedToken(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	resetToken, err := queries.CreatePasswordResetToken(context.Background(), db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     "used-reset-token-hex-string-64-chars-long-enough-t",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// First reset succeeds
	err = svc.ResetPassword(context.Background(), resetToken.Token, "FirstNew@Pass1")
	require.NoError(t, err)

	// Second reset with same token fails
	err = svc.ResetPassword(context.Background(), resetToken.Token, "SecondNew@Pass1")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrResetTokenUsed)
}

// TestResetPassword_InvalidToken verifies that non-existent tokens are rejected.
func TestResetPassword_InvalidToken(t *testing.T) {
	svc, _, _ := setupPasswordResetTest(t)

	err := svc.ResetPassword(context.Background(), "invalid-token", "NewPass@2026")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrResetTokenInvalid)
}

// TestResetPassword_WeakPassword verifies that weak passwords are rejected.
func TestResetPassword_WeakPassword(t *testing.T) {
	svc, dbConn, userID := setupPasswordResetTest(t)
	defer dbConn.Close()

	queries := db.New(dbConn)

	resetToken, err := queries.CreatePasswordResetToken(context.Background(), db.CreatePasswordResetTokenParams{
		UserID:    userID,
		Token:     "weak-pw-token-hex-string-64-chars-long-enough-for-t",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	// Test too short
	err = svc.ResetPassword(context.Background(), resetToken.Token, "Short1!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "8 characters")

	// Test missing uppercase
	err = svc.ResetPassword(context.Background(), resetToken.Token, "lowercase@pass1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "uppercase")

	// Test missing digit
	err = svc.ResetPassword(context.Background(), resetToken.Token, "NoDigit@Pass")
	require.Error(t, err)
	require.Contains(t, err.Error(), "digit")
}

// TestGenerateResetToken verifies token generation produces 64-char hex string.
func TestGenerateResetToken(t *testing.T) {
	token, err := generateResetToken()
	require.NoError(t, err)
	require.Len(t, token, 64) // 32 bytes = 64 hex chars
	require.NotEmpty(t, token)

	// Verify uniqueness (highly unlikely to collide)
	token2, err := generateResetToken()
	require.NoError(t, err)
	require.NotEqual(t, token, token2)
}

// TestPasswordResetDomainTypes verifies DTO JSON tags.
func TestPasswordResetDomainTypes(t *testing.T) {
	req := domain.ResetTokenRequest{Email: "user@example.com"}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	require.Contains(t, string(b), `"email":"user@example.com"`)

	resetReq := domain.ResetPasswordRequest{Token: "abc", NewPassword: "New@Pass1"}
	b, err = json.Marshal(resetReq)
	require.NoError(t, err)
	require.Contains(t, string(b), `"token":"abc"`)
	require.Contains(t, string(b), `"new_password":"New@Pass1"`)
}
