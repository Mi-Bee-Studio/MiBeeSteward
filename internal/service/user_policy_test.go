// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package service

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
)

// longPassword passes every policy class (upper+lower+digit+special) but
// exceeds bcrypt's 72-byte input cap, making the hash step fail
// deterministically, the seam every "failed to hash password" branch needs.
var longPassword = "Aa1!" + strings.Repeat("a", 100)

// TestValidatePassword_LowercaseMissing pins the lowercase rule in both
// directions: length-only default accepts an all-uppercase+digits password,
// and the rule fires when the class is turned on.
func TestValidatePassword_LowercaseMissing(t *testing.T) {
	svc, _ := setupUserService(t)
	_, err := svc.Register(context.Background(), "u1", "u1@invalid", "ABCDEFG1", "user")
	require.NoError(t, err, "length-only default must accept uppercase+digits without lowercase")

	svc2, _ := setupUserService(t)
	svc2.policy = config.PasswordPolicyConfig{MinLength: 8, RequireUppercase: true, RequireLowercase: true, RequireDigit: true}
	_, err = svc2.Register(context.Background(), "u2", "u2@invalid", "ABCDEFG1", "user")
	require.ErrorContains(t, err, "lowercase")
}

// TestEffectivePolicy_DefaultsWhenZero: a service built with the zero policy
// (never run through config defaults seeding) falls back to
// DefaultPasswordPolicy on reads.
func TestEffectivePolicy_DefaultsWhenZero(t *testing.T) {
	svc, _ := setupUserService(t)
	require.Equal(t, DefaultPasswordPolicy(), svc.effectivePolicy())
}

// TestEffectiveLockout_LocalPolicy pins the lockout resolution: the policy
// set via SetLockoutPolicy is what effectiveLockout answers.
func TestEffectiveLockout_LocalPolicy(t *testing.T) {
	svc, _ := setupUserService(t)
	svc.SetLockoutPolicy(config.LockoutConfig{MaxFailedAttempts: 7, LockMinutes: 15})
	got := svc.effectiveLockout()
	require.Equal(t, 7, got.MaxFailedAttempts)
}

// TestCompleteSetup_Tails walks the first-run completion branches: no pending
// setup user → ErrNoPendingSetup; pending user + un-hashable password →
// error; pending user + dead DB → update error.
func TestCompleteSetup_Tails(t *testing.T) {
	svc, db := setupUserService(t)
	ctx := context.Background()

	_, err := svc.CompleteSetup(ctx, "Str0ng!Pass")
	require.ErrorIs(t, err, ErrNoPendingSetup)

	// Seed the empty-password admin, then exceed bcrypt's 72-byte cap.
	_, err = svc.SeedAdmin(ctx, "admin@invalid", "")
	require.NoError(t, err)
	_, err = svc.CompleteSetup(ctx, longPassword)
	require.ErrorContains(t, err, "hash")

	// The failed attempts left the pending row intact; kill the handle so the
	// pending-user LOOKUP itself fails (the generic-error wrap).
	require.NoError(t, db.Close())
	_, err = svc.CompleteSetup(ctx, "Str0ng!Pass")
	require.ErrorContains(t, err, "failed to get pending setup user")
}

// TestUserProfileAndPassword_Tails sweeps the generic-error wraps (dead DB
// handle) of the profile/password paths, the ErrNoRows "user not found"
// branches are covered elsewhere; these are the non-sentinel failures.
func TestUserProfileAndPassword_Tails(t *testing.T) {
	svc, db := setupUserService(t)
	ctx := context.Background()
	u := registerTestUser(t, svc, "tailu", "tailu@invalid")
	old := "Str0ng!Pass"

	// Un-hashable NEW password (correct old, live DB) fails at the hash step.
	require.ErrorContains(t, svc.ChangePassword(ctx, u.ID, old, longPassword), "hash")
	require.ErrorContains(t, svc.ForceChangePassword(ctx, u.ID, longPassword), "hash")
	require.ErrorContains(t, svc.AdminResetPassword(ctx, u.ID, longPassword), "hash")

	// Dead handle: every first-lookup wraps its generic query error.
	require.NoError(t, db.Close())
	_, err := svc.GetProfile(ctx, u.ID)
	require.ErrorContains(t, err, "failed to get user")
	_, err = svc.UpdateProfile(ctx, u.ID, "new@invalid")
	require.ErrorContains(t, err, "failed to get user")
	require.ErrorContains(t, svc.ChangePassword(ctx, u.ID, old, "Str0nger!Pass"), "failed to get user")
	require.ErrorContains(t, svc.ForceChangePassword(ctx, u.ID, "Str0nger!Pass"), "failed to get user")
	require.ErrorContains(t, svc.AdminResetPassword(ctx, u.ID, "Str0nger!Pass"), "failed to get user")
	require.Error(t, svc.SetMustChangePassword(ctx, u.ID, true))
}

// TestLogin_TwoFactorRequiredChallenge pins the 2FA branch: an enrolled user
// gets the challenge response (empty token + TwoFactorRequired) instead of a
// session.
func TestLogin_TwoFactorRequiredChallenge(t *testing.T) {
	svc, db := setupUserService(t)
	ctx := context.Background()
	u := registerTestUser(t, svc, "tfu", "tfu@invalid")

	// The users-table harness lacks the TOTP satellite; add it and enroll
	// directly at the storage layer, the branch only needs IsEnabled=true.
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS user_totp (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
		secret TEXT NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		backup_codes TEXT NOT NULL DEFAULT '[]',
		enabled INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO user_totp (user_id, secret, verified, enabled) VALUES (?, 'JBSWY3DPEHPK3PXP', 1, 1)`, u.ID)
	require.NoError(t, err)
	svc.SetTOTPService(NewTOTPService(db, nil))

	resp, err := svc.Login(ctx, "tfu", "Str0ng!Pass")
	require.NoError(t, err)
	require.True(t, resp.TwoFactorRequired, "enrolled user must receive the 2FA challenge")
	require.Empty(t, resp.Token, "no session token before the second factor")

	// Wrong password still fails outright even when enrolled.
	_, err = svc.Login(ctx, "tfu", "wrong")
	require.Error(t, err)
}

// TestGenerateTokenForUser_Nonexistent is a light sanity net for the token
// helpers' error tails (nonexistent user → error, no version).
func TestGenerateTokenForUser_Nonexistent(t *testing.T) {
	svc, _ := setupUserService(t)
	_, err := svc.GenerateTokenForUser(context.Background(), 424242, "user", false)
	require.Error(t, err)
	_, ok := svc.TokenVersion(context.Background(), 424242)
	require.False(t, ok)
}
