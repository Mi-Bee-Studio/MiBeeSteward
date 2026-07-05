package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
	"mibee-steward/internal/domain"
)

const testJWTSecret = "test-secret-which-is-at-least-32-chars-long"

// setupUserService creates an in-memory SQLite DB with the users table
// and returns a UserService ready for testing.
func setupUserService(t *testing.T) (*UserService, *sql.DB) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Create users table matching all migrations (000001 + 000003 + 000004)
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			failed_login_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until TIMESTAMP,
			password_changed_at DATETIME,
			must_change_password BOOLEAN NOT NULL DEFAULT 0
		)
	`)
	require.NoError(t, err)

	svc := NewUserService(db, testJWTSecret, 24*time.Hour)
	return svc, db
}

// registerTestUser is a helper that registers a user with a strong password.
func registerTestUser(t *testing.T, svc *UserService, username, email string) *domain.UserResponse {
	t.Helper()
	resp, err := svc.Register(context.Background(), username, email, "Str0ng!Pass", "user")
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

// ---------- Test Cases ----------

func TestRegister_Success(t *testing.T) {
	svc, _ := setupUserService(t)

	resp, err := svc.Register(context.Background(), "alice", "alice@example.com", "Str0ng!Pass", "user")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify response fields
	require.Equal(t, "alice", resp.Username)
	require.Equal(t, "alice@example.com", resp.Email)
	require.Equal(t, "user", resp.Role)
	require.NotZero(t, resp.ID)
	require.NotZero(t, resp.CreatedAt)
	require.False(t, resp.MustChangePassword)
}

func TestRegister_DefaultRole(t *testing.T) {
	svc, _ := setupUserService(t)

	resp, err := svc.Register(context.Background(), "bob", "bob@example.com", "Str0ng!Pass", "")
	require.NoError(t, err)
	require.Equal(t, "user", resp.Role)
}

func TestRegister_DuplicateUsername(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Register(context.Background(), "alice", "alice@example.com", "Str0ng!Pass", "user")
	require.NoError(t, err)

	_, err = svc.Register(context.Background(), "alice", "alice2@example.com", "Str0ng!Pass", "user")
	require.True(t, errors.Is(err, ErrUserExists), "expected ErrUserExists, got: %v", err)
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Register(context.Background(), "alice", "alice@example.com", "Str0ng!Pass", "user")
	require.NoError(t, err)

	_, err = svc.Register(context.Background(), "alice2", "alice@example.com", "Str0ng!Pass", "user")
	require.True(t, errors.Is(err, ErrUserExists), "expected ErrUserExists, got: %v", err)
}

func TestRegister_PasswordTooShort(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Register(context.Background(), "charlie", "charlie@example.com", "Ab1!", "user")
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 8 characters")
}

func TestRegister_PasswordMissingUppercase(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Register(context.Background(), "dave", "dave@example.com", "lower123!@#", "user")
	require.Error(t, err)
	require.Contains(t, err.Error(), "uppercase")
}

func TestRegister_PasswordMissingDigit(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Register(context.Background(), "eve", "eve@example.com", "NoDigits!!", "user")
	require.Error(t, err)
	require.Contains(t, err.Error(), "digit")
}

func TestRegister_PasswordMissingSpecial(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Register(context.Background(), "frank", "frank@example.com", "NoSpecial123", "user")
	require.Error(t, err)
	require.Contains(t, err.Error(), "special")
}

func TestRegister_PasswordEqualsUsername(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Register(context.Background(), "grace", "grace@example.com", "Gr4ce!grace", "user")
	// Not equal to username, this should succeed
	require.NoError(t, err)

	// Now try with password equal to username (needs to meet complexity too)
	_, err = svc.Register(context.Background(), "Hrack123!", "hrack@example.com", "Hrack123!", "user")
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not equal username")
}

func TestLogin_Success(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")

	resp, err := svc.Login(context.Background(), "alice", "Str0ng!Pass")
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify token present
	require.NotEmpty(t, resp.Token, "login should return a JWT token")

	// Verify user fields
	require.Equal(t, "alice", resp.User.Username)
	require.Equal(t, "alice@example.com", resp.User.Email)
	require.Equal(t, "user", resp.User.Role)
}

func TestLogin_WithEmail(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")

	resp, err := svc.Login(context.Background(), "alice@example.com", "Str0ng!Pass")
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Token)
	require.Equal(t, "alice", resp.User.Username)
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")

	_, err := svc.Login(context.Background(), "alice", "WrongPass1!")
	require.True(t, errors.Is(err, ErrInvalidCredentials), "expected ErrInvalidCredentials, got: %v", err)
}

func TestLogin_UserNotFound(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.Login(context.Background(), "nonexistent", "Str0ng!Pass")
	require.True(t, errors.Is(err, ErrInvalidCredentials), "expected ErrInvalidCredentials, got: %v", err)
}

func TestLogin_AccountLockout(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "lockme", "lockme@example.com")

	// Fail 5 times to trigger lockout
	for i := 0; i < 5; i++ {
		_, err := svc.Login(context.Background(), "lockme", "WrongPass1!")
			require.True(t, errors.Is(err, ErrInvalidCredentials))
	}

	// 6th attempt with correct password should be locked
	_, err := svc.Login(context.Background(), "lockme", "Str0ng!Pass")
	require.True(t, errors.Is(err, ErrAccountLocked), "expected ErrAccountLocked after 5 failed attempts, got: %v", err)
}

func TestLogin_ResetsAttemptsOnSuccess(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "resetme", "resetme@example.com")

	// Fail 3 times
	for i := 0; i < 3; i++ {
		_, err := svc.Login(context.Background(), "resetme", "WrongPass1!")
			require.True(t, errors.Is(err, ErrInvalidCredentials))
	}

	// Succeed — resets counter
	_, err := svc.Login(context.Background(), "resetme", "Str0ng!Pass")
	require.NoError(t, err)

	// Fail 3 more times — should NOT be locked (counter was reset)
	for i := 0; i < 3; i++ {
		_, err := svc.Login(context.Background(), "resetme", "WrongPass1!")
			require.True(t, errors.Is(err, ErrInvalidCredentials))
	}

	// 4th correct login should still work (only 3 fails after reset)
	_, err = svc.Login(context.Background(), "resetme", "Str0ng!Pass")
	require.NoError(t, err)
}

func TestChangePassword_Success(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")

	err := svc.ChangePassword(context.Background(), 1, "Str0ng!Pass", "N3wP@ssword!")
	require.NoError(t, err)

	// Verify can login with new password
	resp, err := svc.Login(context.Background(), "alice", "N3wP@ssword!")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Token)
}

func TestChangePassword_WrongOldPassword(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")

	err := svc.ChangePassword(context.Background(), 1, "WrongOld1!", "N3wP@ssword!")
	require.True(t, errors.Is(err, ErrInvalidCredentials), "expected ErrInvalidCredentials, got: %v", err)
}

func TestChangePassword_WeakNewPassword(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")

	err := svc.ChangePassword(context.Background(), 1, "Str0ng!Pass", "weak")
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 8 characters")
}

func TestChangePassword_UserNotFound(t *testing.T) {
	svc, _ := setupUserService(t)

	err := svc.ChangePassword(context.Background(), 9999, "old", "N3wP@ssword!")
	require.True(t, errors.Is(err, ErrUserNotFound), "expected ErrUserNotFound, got: %v", err)
}

func TestForceChangePassword_Success(t *testing.T) {
	svc, _ := setupUserService(t)

	user := registerTestUser(t, svc, "alice", "alice@example.com")

	// Set must_change_password flag
	err := svc.SetMustChangePassword(context.Background(), user.ID, true)
	require.NoError(t, err)

	// Verify flag is set
	profile, err := svc.GetProfile(context.Background(), user.ID)
	require.NoError(t, err)
	require.True(t, profile.MustChangePassword)

	// Force change password
	err = svc.ForceChangePassword(context.Background(), user.ID, "F0rc3!NewPass")
	require.NoError(t, err)

	// Verify must_change_password is cleared
	profile, err = svc.GetProfile(context.Background(), user.ID)
	require.NoError(t, err)
	require.False(t, profile.MustChangePassword)

	// Verify login works with new password
	_, err = svc.Login(context.Background(), "alice", "F0rc3!NewPass")
	require.NoError(t, err)
}

func TestForceChangePassword_WeakPassword(t *testing.T) {
	svc, _ := setupUserService(t)

	user := registerTestUser(t, svc, "alice", "alice@example.com")

	err := svc.ForceChangePassword(context.Background(), user.ID, "weak")
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 8 characters")
}

func TestForceChangePassword_UserNotFound(t *testing.T) {
	svc, _ := setupUserService(t)

	err := svc.ForceChangePassword(context.Background(), 9999, "F0rc3!NewPass")
	require.True(t, errors.Is(err, ErrUserNotFound), "expected ErrUserNotFound, got: %v", err)
}

func TestGetProfile_Success(t *testing.T) {
	svc, _ := setupUserService(t)

	created := registerTestUser(t, svc, "alice", "alice@example.com")

	profile, err := svc.GetProfile(context.Background(), created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, profile.ID)
	require.Equal(t, "alice", profile.Username)
	require.Equal(t, "alice@example.com", profile.Email)
	require.Equal(t, "user", profile.Role)
}

func TestGetProfile_NotFound(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.GetProfile(context.Background(), 9999)
	require.True(t, errors.Is(err, ErrUserNotFound), "expected ErrUserNotFound, got: %v", err)
}

func TestUpdateProfile_Success(t *testing.T) {
	svc, _ := setupUserService(t)

	created := registerTestUser(t, svc, "alice", "alice@example.com")

	updated, err := svc.UpdateProfile(context.Background(), created.ID, "newalice@example.com")
	require.NoError(t, err)
	require.Equal(t, "newalice@example.com", updated.Email)
	require.Equal(t, "alice", updated.Username) // username unchanged
}

func TestUpdateProfile_NotFound(t *testing.T) {
	svc, _ := setupUserService(t)

	_, err := svc.UpdateProfile(context.Background(), 9999, "noone@example.com")
	require.True(t, errors.Is(err, ErrUserNotFound), "expected ErrUserNotFound, got: %v", err)
}

func TestListUsers(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")
	registerTestUser(t, svc, "bob", "bob@example.com")
	registerTestUser(t, svc, "charlie", "charlie@example.com")

	resp, err := svc.ListUsers(context.Background(), 10, 0)
	require.NoError(t, err)
	require.Len(t, resp.Users, 3)
	require.Equal(t, 3, resp.Total)
}

func TestListUsers_Pagination(t *testing.T) {
	svc, _ := setupUserService(t)

	registerTestUser(t, svc, "alice", "alice@example.com")
	registerTestUser(t, svc, "bob", "bob@example.com")
	registerTestUser(t, svc, "charlie", "charlie@example.com")

	// Get first page of 2
	resp, err := svc.ListUsers(context.Background(), 2, 0)
	require.NoError(t, err)
	require.Len(t, resp.Users, 2)
	require.Equal(t, 2, resp.Total) // Total is len of returned users, not total count

	// Get second page
	resp, err = svc.ListUsers(context.Background(), 2, 2)
	require.NoError(t, err)
	require.Len(t, resp.Users, 1)
}

func TestRegister_AdminRole(t *testing.T) {
	svc, _ := setupUserService(t)

	resp, err := svc.Register(context.Background(), "admin1", "admin1@example.com", "Adm1n!Pass", "admin")
	require.NoError(t, err)
	require.Equal(t, "admin", resp.Role)
}
