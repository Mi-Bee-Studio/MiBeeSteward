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

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrSamePassword       = errors.New("new password must be different")
	ErrAccountLocked      = errors.New("account is locked due to too many failed login attempts")
	// ErrWeakPassword is the sentinel for every password-strength rule failure.
	// validatePassword wraps the specific rule as detail, so handlers map the
	// whole family to 400 via errors.Is(err, ErrWeakPassword) without checking
	// each rule individually. (#165)
	ErrWeakPassword = errors.New("password does not meet requirements")
)

var (
	hasUppercase   = regexp.MustCompile(`[A-Z]`)
	hasLowercase   = regexp.MustCompile(`[a-z]`)
	hasDigit       = regexp.MustCompile(`[0-9]`)
	hasSpecialChar = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
)

// DefaultPasswordPolicy reproduces the strength rules that used to be
// hardcoded in validatePassword: length ≥8 plus all four character classes.
// Callers that build a UserService without going through config.Load (unit
// tests, zero-valued configs) fall back to this — behavior is unchanged for
// them.
func DefaultPasswordPolicy() config.PasswordPolicyConfig {
	return config.PasswordPolicyConfig{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}
}

// validatePassword checks password strength per the configured policy
// (auth.password_policy). The must-not-equal-username rule is always on — it
// is an identity guard, not a strength knob. Every failure wraps
// ErrWeakPassword so handlers map the family to 400 via errors.Is (#165).
func validatePassword(policy config.PasswordPolicyConfig, password, username string) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, policy.MinLength)
	}
	if password == username {
		return fmt.Errorf("%w: must not equal username", ErrWeakPassword)
	}
	if policy.RequireUppercase && !hasUppercase.MatchString(password) {
		return fmt.Errorf("%w: must contain at least one uppercase letter", ErrWeakPassword)
	}
	if policy.RequireLowercase && !hasLowercase.MatchString(password) {
		return fmt.Errorf("%w: must contain at least one lowercase letter", ErrWeakPassword)
	}
	if policy.RequireDigit && !hasDigit.MatchString(password) {
		return fmt.Errorf("%w: must contain at least one digit", ErrWeakPassword)
	}
	if policy.RequireSpecial && !hasSpecialChar.MatchString(password) {
		return fmt.Errorf("%w: must contain at least one special character", ErrWeakPassword)
	}
	return nil
}

// zeroPolicy reports whether policy is the zero value — a config that never
// went through Load's defaults seeding. Treated as "use the defaults" so
// hand-constructed configs (tests) keep the historical behavior.
func zeroPolicy(p config.PasswordPolicyConfig) bool {
	return p.MinLength == 0 && !p.RequireUppercase && !p.RequireLowercase &&
		!p.RequireDigit && !p.RequireSpecial
}

// UserService handles user authentication and management operations.
type UserService struct {
	queries *db.Queries
	auth    *jwtauth.JWTAuth
	expiry  time.Duration
	totpSvc *TOTPService
	policy  config.PasswordPolicyConfig
	lockout config.LockoutConfig
}

func NewUserService(dbConn db.DBTX, jwtSecret string, tokenExpiry time.Duration, passwordPolicy config.PasswordPolicyConfig) *UserService {
	if zeroPolicy(passwordPolicy) {
		passwordPolicy = DefaultPasswordPolicy()
	}
	return &UserService{
		queries: db.New(dbConn),
		auth:    jwtauth.New("HS256", []byte(jwtSecret), nil),
		expiry:  tokenExpiry,
		policy:  passwordPolicy,
	}
}

// SetTOTPService injects the TOTPService dependency (set after construction to avoid circular deps).
func (s *UserService) SetTOTPService(totpSvc *TOTPService) {
	s.totpSvc = totpSvc
}

// SetLockoutPolicy injects the failed-login lockout tuning (auth.lockout).
// Zero value keeps the historical defaults (5 attempts / 30 minutes), so
// constructions that never call this (unit tests) behave as before.
func (s *UserService) SetLockoutPolicy(l config.LockoutConfig) {
	s.lockout = l
}

// lockoutParams resolves the effective lockout tuning, defaulting the
// historical hardcoded values when unset.
func (s *UserService) lockoutParams() (maxAttempts int, lockMinutes int) {
	maxAttempts = s.lockout.MaxFailedAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	lockMinutes = s.lockout.LockMinutes
	if lockMinutes <= 0 {
		lockMinutes = 30
	}
	return
}

// Register creates a new user with the given credentials.
func (s *UserService) Register(ctx context.Context, username, email, password, role string) (*domain.UserResponse, error) {
	if role == "" {
		role = string(domain.RoleUser)
	}

	if err := validatePassword(s.policy, password, username); err != nil {
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

	// Check if account is locked. Carrying the remaining minutes in the error
	// lets the handler return 423 (distinct from the 429 rate limiter) so the
	// UI can tell "account locked" from "too many attempts from this IP".
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		mins := int(time.Until(*user.LockedUntil).Minutes()) + 1
		return nil, fmt.Errorf("%w: retry after %d minutes", ErrAccountLocked, mins)
	}
	// A lock that has expired resets the failure counter: each lockout cycle
	// costs a fresh maxAttempts failures. Without this, a single stray retry
	// after expiry re-locked instantly — combined with a periodic automation
	// using a stale password that meant an effectively indefinite lock.
	if user.LockedUntil != nil {
		if err := s.queries.ResetLoginAttempts(ctx, user.ID); err != nil {
			slog.Warn("failed to reset expired lockout", "user_id", user.ID, "error", err)
		} else {
			user.FailedLoginAttempts = 0
			user.LockedUntil = nil
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Increment failed login attempts (threshold/duration configurable
		// via auth.lockout; defaults preserve the historical behavior).
		maxAttempts, lockMinutes := s.lockoutParams()
		attempts := user.FailedLoginAttempts + 1
		var lockedUntil *time.Time
		if attempts >= int64(maxAttempts) {
			lockTime := time.Now().Add(time.Duration(lockMinutes) * time.Minute)
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

	if err := validatePassword(s.policy, newPassword, user.Username); err != nil {
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

	if err := validatePassword(s.policy, newPassword, user.Username); err != nil {
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

	if err := validatePassword(s.policy, newPassword, user.Username); err != nil {
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
func (s *UserService) ListUsers(ctx context.Context, search string, limit, offset int64) (*domain.ListUsersResponse, error) {
	users, err := s.queries.ListUsers(ctx, db.ListUsersParams{
		Column1: search,
		LOWER:   search,
		LOWER_2: search,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	resp := make([]domain.UserResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, toUserResponse(u))
	}

	// Total is the real match count (previously len(page), which capped at the
	// page size and broke pagination when more than one page matched).
	total, err := s.queries.CountUsers(ctx, db.CountUsersParams{
		Column1: search,
		LOWER:   search,
		LOWER_2: search,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}

	return &domain.ListUsersResponse{
		Users: resp,
		Total: int(total),
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
