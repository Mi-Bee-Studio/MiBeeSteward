package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"

	_ "modernc.org/sqlite"
)

// setupTOTPTest creates an in-memory SQLite DB with the users and user_totp tables
// and returns a TOTPService and helper dependencies ready for testing.
func setupTOTPTest(t *testing.T) (*TOTPService, *sql.DB, *db.Queries, int64) {
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

	// Create user_totp table
	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS user_totp (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER UNIQUE NOT NULL,
			secret TEXT NOT NULL,
			verified INTEGER NOT NULL DEFAULT 0,
			backup_codes TEXT NOT NULL DEFAULT '[]',
			enabled INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	require.NoError(t, err)

	queries := db.New(dbConn)

	// Create a test user
	hash, err := bcrypt.GenerateFromPassword([]byte("Test@2026"), bcrypt.DefaultCost)
	require.NoError(t, err)

	result, err := dbConn.Exec(
		`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		"testuser", "test@example.com", string(hash), "admin",
	)
	require.NoError(t, err)

	userID, err := result.LastInsertId()
	require.NoError(t, err)

	svc := NewTOTPService(dbConn, nil)
	return svc, dbConn, queries, userID
}

func TestTOTP_Setup(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Secret)
	require.NotEmpty(t, resp.QRCodeURL)
	require.Contains(t, resp.QRCodeURL, "otpauth://totp")

	// Verify backup codes
	var codes []string
	err = json.Unmarshal(resp.BackupCodes, &codes)
	require.NoError(t, err)
	require.Len(t, codes, 10)
	for _, code := range codes {
		require.Len(t, code, 8, "backup code should be 8 characters")
	}

	// Verify QR URL contains issuer (URL-encoded)
	require.Contains(t, resp.QRCodeURL, "MiBee%20Steward")
}

func TestTOTP_Setup_UpsertResetsState(t *testing.T) {
	svc, dbConn, _, userID := setupTOTPTest(t)

	// First setup
	resp1, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	// Manually enable 2FA
	_, err = dbConn.Exec(`UPDATE user_totp SET verified=1, enabled=1 WHERE user_id=?`, userID)
	require.NoError(t, err)

	// Second setup should reset
	resp2, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)
	require.NotEqual(t, resp1.Secret, resp2.Secret, "secret should change on re-setup")

	// Verify state is reset
	var verified, enabled int
	row := dbConn.QueryRow(`SELECT verified, enabled FROM user_totp WHERE user_id=?`, userID)
	require.NoError(t, row.Scan(&verified, &enabled))
	require.Equal(t, 0, verified)
	require.Equal(t, 0, enabled)
}

func TestTOTP_Enable_ValidCode(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Setup first
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	// Generate a valid code from the secret
	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)

	// Enable with valid code
	err = svc.Enable(context.Background(), userID, code)
	require.NoError(t, err)

	// Verify it's enabled
	enabled, err := svc.IsEnabled(context.Background(), userID)
	require.NoError(t, err)
	require.True(t, enabled)
}

func TestTOTP_Enable_InvalidCode(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Setup first
	_, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	// Enable with invalid code
	err = svc.Enable(context.Background(), userID, "000000")
	require.ErrorIs(t, err, ErrInvalidTOTPCode)

	// Verify it's NOT enabled
	enabled, err := svc.IsEnabled(context.Background(), userID)
	require.NoError(t, err)
	require.False(t, enabled)
}

func TestTOTP_Enable_NotSetup(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Try to enable without setup
	err := svc.Enable(context.Background(), userID, "123456")
	require.ErrorIs(t, err, ErrTOTPNotFound)
}

func TestTOTP_Verify_ValidCode(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Setup + enable
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)

	err = svc.Enable(context.Background(), userID, code)
	require.NoError(t, err)

	// Generate a new code for verification
	verifyCode, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)

	// Verify
	err = svc.Verify(context.Background(), userID, verifyCode)
	require.NoError(t, err)
}

func TestTOTP_Verify_BackupCode(t *testing.T) {
	svc, dbConn, _, userID := setupTOTPTest(t)

	// Setup + enable
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)
	err = svc.Enable(context.Background(), userID, code)
	require.NoError(t, err)

	// Get backup codes
	var backupCodes []string
	err = json.Unmarshal(resp.BackupCodes, &backupCodes)
	require.NoError(t, err)
	require.NotEmpty(t, backupCodes)

	// Use first backup code
	backupCode := backupCodes[0]
	err = svc.Verify(context.Background(), userID, backupCode)
	require.NoError(t, err)

	// Verify the backup code was consumed
	var updatedCodes []string
	row := dbConn.QueryRow(`SELECT backup_codes FROM user_totp WHERE user_id=?`, userID)
	var codesJSON string
	require.NoError(t, row.Scan(&codesJSON))
	json.Unmarshal([]byte(codesJSON), &updatedCodes)
	require.Len(t, updatedCodes, 9, "backup code should be consumed")

	// The used code should no longer be in the list
	for _, c := range updatedCodes {
		require.NotEqual(t, backupCode, c, "used backup code should be removed")
	}

	// Using the same backup code again should fail
	err = svc.Verify(context.Background(), userID, backupCode)
	require.ErrorIs(t, err, ErrInvalidTOTPCode)
}

func TestTOTP_Verify_NotEnabled(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Setup but DON'T enable
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)

	// Verify should fail because 2FA is not enabled
	err = svc.Verify(context.Background(), userID, code)
	require.ErrorIs(t, err, ErrTOTPNotEnabled)
}

func TestTOTP_Disable_ValidPassword(t *testing.T) {
	svc, dbConn, _, userID := setupTOTPTest(t)

	// Setup + enable
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)
	err = svc.Enable(context.Background(), userID, code)
	require.NoError(t, err)

	// Disable with correct password
	err = svc.Disable(context.Background(), userID, "Test@2026")
	require.NoError(t, err)

	// Verify TOTP is deleted
	var count int
	dbConn.QueryRow(`SELECT COUNT(*) FROM user_totp WHERE user_id=?`, userID).Scan(&count)
	require.Equal(t, 0, count)
}

func TestTOTP_Disable_InvalidPassword(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Setup + enable
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)
	err = svc.Enable(context.Background(), userID, code)
	require.NoError(t, err)

	// Disable with wrong password
	err = svc.Disable(context.Background(), userID, "WrongPassword!")
	require.ErrorIs(t, err, ErrTOTPInvalidPassword)
}

func TestTOTP_GetStatus(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Status when no TOTP
	status, err := svc.GetStatus(context.Background(), userID)
	require.NoError(t, err)
	require.NotNil(t, status)
	require.False(t, status.Enabled)
	require.False(t, status.Verified)

	// Setup
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)
	err = svc.Enable(context.Background(), userID, code)
	require.NoError(t, err)

	// Status when enabled
	status, err = svc.GetStatus(context.Background(), userID)
	require.NoError(t, err)
	require.True(t, status.Enabled)
	require.True(t, status.Verified)
}

func TestTOTP_IsEnabled(t *testing.T) {
	svc, _, _, userID := setupTOTPTest(t)

	// Not enabled
	enabled, err := svc.IsEnabled(context.Background(), userID)
	require.NoError(t, err)
	require.False(t, enabled)

	// Setup + enable
	resp, err := svc.Setup(context.Background(), userID, "testuser")
	require.NoError(t, err)

	code, err := totp.GenerateCode(resp.Secret, time.Now())
	require.NoError(t, err)
	err = svc.Enable(context.Background(), userID, code)
	require.NoError(t, err)

	// Now enabled
	enabled, err = svc.IsEnabled(context.Background(), userID)
	require.NoError(t, err)
	require.True(t, enabled)
}

func TestTOTP_GenerateBackupCodes(t *testing.T) {
	codes := generateBackupCodes(10)
	require.Len(t, codes, 10)
	for _, code := range codes {
		require.Len(t, code, 8)
		// Verify alphanumeric
		for _, c := range code {
			require.True(t,
				(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
				"backup code should be alphanumeric, got: %c", c,
			)
		}
	}
}

func TestDomainTOTPDTOs(t *testing.T) {
	// Verify TOTPSetupResponse JSON tags
	resp := domain.TOTPSetupResponse{
		Secret:      "TESTSECRET",
		BackupCodes: json.RawMessage(`["abc12345","def67890"]`),
		QRCodeURL:   "otpauth://totp/MiBee+Steward:testuser?secret=TESTSECRET",
	}
	data, err := json.Marshal(resp)
	require.NoError(t, err)
	require.Contains(t, string(data), `"secret":"TESTSECRET"`)
	require.Contains(t, string(data), `"qr_code_url"`)

	// Verify TOTPStatusResponse
	status := domain.TOTPStatusResponse{
		Enabled:  true,
		Verified: true,
	}
	data, err = json.Marshal(status)
	require.NoError(t, err)
	require.Contains(t, string(data), `"enabled":true`)

	// Verify TOTPLoginChallengeResponse
	challenge := domain.TOTPLoginChallengeResponse{
		Require2FA: true,
		User: domain.UserResponse{
			ID:       1,
			Username: "testuser",
		},
	}
	data, err = json.Marshal(challenge)
	require.NoError(t, err)
	require.Contains(t, string(data), `"require_2fa":true`)

	// Verify LoginResponse with TwoFactorRequired
	loginResp := domain.LoginResponse{
		Token:             "",
		User:              domain.UserResponse{ID: 1, Username: "testuser"},
		TwoFactorRequired: true,
	}
	data, err = json.Marshal(loginResp)
	require.NoError(t, err)
	require.Contains(t, string(data), `"two_factor_required":true`)

	// When two_factor_required is false, it should be omitted
	loginResp2 := domain.LoginResponse{
		Token: "jwt-token",
		User:  domain.UserResponse{ID: 1, Username: "testuser"},
	}
	data, err = json.Marshal(loginResp2)
	require.NoError(t, err)
	require.NotContains(t, string(data), `"two_factor_required"`)
}
