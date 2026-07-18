// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrSamePassword       = errors.New("new password must be different")
	ErrAccountLocked      = errors.New("account is locked due to too many failed login attempts")
)

var (
	hasUppercase   = regexp.MustCompile(`[A-Z]`)
	hasLowercase   = regexp.MustCompile(`[a-z]`)
	hasDigit       = regexp.MustCompile(`[0-9]`)
	hasSpecialChar = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
)

// validatePassword checks password strength: length ≥8, no match with username,
// and requires at least one uppercase, lowercase, digit, and special character.
func validatePassword(password, username string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if password == username {
		return fmt.Errorf("password must not equal username")
	}
	if !hasUppercase.MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLowercase.MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit.MatchString(password) {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSpecialChar.MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}

// UserService handles user authentication and management operations.
type UserService struct {
	queries *db.Queries
	auth    *jwtauth.JWTAuth
	expiry  time.Duration
	totpSvc *TOTPService
}

func NewUserService(dbConn db.DBTX, jwtSecret string, tokenExpiry time.Duration) *UserService {
	return &UserService{
		queries: db.New(dbConn),
		auth:    jwtauth.New("HS256", []byte(jwtSecret), nil),
		expiry:  tokenExpiry,
	}
}

// SetTOTPService injects the TOTPService dependency (set after construction to avoid circular deps).
func (s *UserService) SetTOTPService(totpSvc *TOTPService) {
	s.totpSvc = totpSvc
}

// Register creates a new user with the given credentials.
func (s *UserService) Register(ctx context.Context, username, email, password, role string) (*domain.UserResponse, error) {
	if role == "" {
		role = string(domain.RoleUser)
	}

	if err := validatePassword(password, username); err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Username:           username,
		Email:              email,
		PasswordHash:       string(hash),
		Role:               role,
		MustChangePassword: false,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserExists, err)
	}

	resp := toUserResponse(user)
	return &resp, nil
}

// Login authenticates a user by username (or email) and password.
// If 2FA is enabled, returns TOTPLoginChallengeResponse instead of JWT.
func (s *UserService) Login(ctx context.Context, username, password string) (*domain.LoginResponse, error) {
	user, err := s.getUserByUsernameOrEmail(ctx, username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Increment failed login attempts
		attempts := user.FailedLoginAttempts + 1
		var lockedUntil *time.Time
		if attempts >= 5 {
			lockTime := time.Now().Add(30 * time.Minute)
			lockedUntil = &lockTime
		}
		if err := s.queries.UpdateLoginAttempts(ctx, db.UpdateLoginAttemptsParams{
			FailedLoginAttempts: attempts,
			LockedUntil:         lockedUntil,
			ID:                  user.ID,
		}); err != nil {
			slog.Warn("failed to update login attempts", "user_id", user.ID, "error", err)
		}
		return nil, ErrInvalidCredentials
	}

	// Reset failed login attempts on success
	if err := s.queries.ResetLoginAttempts(ctx, user.ID); err != nil {
		slog.Warn("failed to reset login attempts", "user_id", user.ID, "error", err)
	}

	// Check if 2FA is enabled
	if s.totpSvc != nil {
		enabled, err := s.totpSvc.IsEnabled(ctx, user.ID)
		if err == nil && enabled {
			// Return 2FA challenge instead of token
			return &domain.LoginResponse{
				Token:             "",
				User:              toUserResponse(user),
				TwoFactorRequired: true,
			}, nil
		}
	}

	token, err := s.generateToken(user.ID, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &domain.LoginResponse{
		Token: token,
		User:  toUserResponse(user),
	}, nil
}

// GetProfile returns the profile of the user with the given ID.
func (s *UserService) GetProfile(ctx context.Context, userID int64) (*domain.UserResponse, error) {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	resp := toUserResponse(user)
	return &resp, nil
}

// UpdateProfile updates the email of the user with the given ID.
func (s *UserService) UpdateProfile(ctx context.Context, userID int64, email string) (*domain.UserResponse, error) {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	updated, err := s.queries.UpdateUser(ctx, db.UpdateUserParams{
		Username:            user.Username,
		Email:               email,
		PasswordHash:        user.PasswordHash,
		Role:                user.Role,
		FailedLoginAttempts: user.FailedLoginAttempts,
		LockedUntil:         user.LockedUntil,
		MustChangePassword:  user.MustChangePassword,
		PasswordChangedAt:   user.PasswordChangedAt,
		ID:                  user.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	resp := toUserResponse(updated)
	return &resp, nil
}

// ChangePassword changes the password for the user with the given ID.
func (s *UserService) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	if err := validatePassword(newPassword, user.Username); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = s.queries.UpdateUser(ctx, db.UpdateUserParams{
		Username:            user.Username,
		Email:               user.Email,
		PasswordHash:        string(hash),
		Role:                user.Role,
		FailedLoginAttempts: user.FailedLoginAttempts,
		LockedUntil:         user.LockedUntil,
		MustChangePassword:  user.MustChangePassword,
		PasswordChangedAt:   user.PasswordChangedAt,
		ID:                  user.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// ForceChangePassword forces a password change for a user (used on first login).
func (s *UserService) ForceChangePassword(ctx context.Context, userID int64, newPassword string) error {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := validatePassword(newPassword, user.Username); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	_, err = s.queries.UpdateUser(ctx, db.UpdateUserParams{
		Username:            user.Username,
		Email:               user.Email,
		PasswordHash:        string(hash),
		Role:                user.Role,
		FailedLoginAttempts: user.FailedLoginAttempts,
		LockedUntil:         user.LockedUntil,
		MustChangePassword:  false,
		PasswordChangedAt:   &now,
		ID:                  user.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// AdminResetPassword resets a user's password as an administrator. Unlike
// ForceChangePassword (which clears the must-change flag for first-login flow),
// this sets MustChangePassword=true so the affected user is forced to pick
// their own password on next login. It also clears any login lockout and
// failure counter so a locked-out user can be immediately unblocked.
func (s *UserService) AdminResetPassword(ctx context.Context, userID int64, newPassword string) error {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := validatePassword(newPassword, user.Username); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	_, err = s.queries.UpdateUser(ctx, db.UpdateUserParams{
		Username:            user.Username,
		Email:               user.Email,
		PasswordHash:        string(hash),
		Role:                user.Role,
		FailedLoginAttempts: 0,    // clear failure counter
		LockedUntil:         nil,  // unlock account
		MustChangePassword:  true, // force user to pick a new password next login
		PasswordChangedAt:   &now,
		ID:                  user.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// ListUsers returns a paginated list of users.
func (s *UserService) ListUsers(ctx context.Context, limit, offset int64) (*domain.ListUsersResponse, error) {
	users, err := s.queries.ListUsers(ctx, db.ListUsersParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	resp := make([]domain.UserResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, toUserResponse(u))
	}

	return &domain.ListUsersResponse{
		Users: resp,
		Total: len(resp),
	}, nil
}

// generateToken creates a signed JWT with user_id and role claims.
func (s *UserService) generateToken(userID int64, role string) (string, error) {
	claims := map[string]interface{}{
		"user_id": userID,
		"role":    role,
		"jti":     randomHex(16),
	}
	jwtauth.SetExpiryIn(claims, s.expiry)
	_, tokenStr, err := s.auth.Encode(claims)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

// GenerateTokenForUser creates a JWT token for a given user (public, used by TOTP handler).
func (s *UserService) GenerateTokenForUser(userID int64, role string) (string, error) {
	return s.generateToken(userID, role)
}

// getUserByUsernameOrEmail looks up a user by username first, then by email.
func (s *UserService) getUserByUsernameOrEmail(ctx context.Context, usernameOrEmail string) (db.User, error) {
	// Try by username first
	user, err := s.queries.GetUserByUsername(ctx, usernameOrEmail)
	if err == nil {
		return user, nil
	}

	// Fallback to email lookup
	return s.queries.GetUserByEmail(ctx, usernameOrEmail)
}

// toUserResponse converts a db.User to a domain.UserResponse (omits password hash).
func toUserResponse(u db.User) domain.UserResponse {
	return domain.UserResponse{
		ID:                 u.ID,
		Username:           u.Username,
		Email:              u.Email,
		Role:               u.Role,
		MustChangePassword: u.MustChangePassword,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}

// SetMustChangePassword sets the must_change_password flag for a user.
func (s *UserService) SetMustChangePassword(ctx context.Context, userID int64, must bool) error {
	return s.queries.SetMustChangePassword(ctx, db.SetMustChangePasswordParams{
		MustChangePassword: must,
		ID:                 userID,
	})
}

// randomHex generates a random hexadecimal string of length 2*n.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
