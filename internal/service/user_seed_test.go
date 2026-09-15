// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"testing"

	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"
)

// SeedAdmin pins the first-run bootstrap contract: the configured
// initial_admin_password is a TEMPORARY credential — it deliberately bypasses
// the password policy (applying the class rules here is what historically
// left fresh installs with no admin at all), the seeded user carries
// must_change_password, and the login token carries the server-side gate
// marker (mcp claim) until the forced change completes.
func TestSeedAdmin_SkipsPolicyAndForcesChange(t *testing.T) {
	svc, _ := setupUserService(t)

	// "weak" fails every class rule of the default policy.
	resp, err := svc.SeedAdmin(context.Background(), "admin@localhost", "weak")
	require.NoError(t, err)
	require.Equal(t, "admin", resp.Username)
	require.Equal(t, "admin", resp.Role)
	require.True(t, resp.MustChangePassword, "seeded admin must be forced to change password")

	login, err := svc.Login(context.Background(), "admin", "weak")
	require.NoError(t, err)
	require.True(t, login.User.MustChangePassword)

	tok, err := jwtauth.VerifyToken(svc.auth, login.Token)
	require.NoError(t, err)
	var mcp bool
	require.NoError(t, tok.Get("mcp", &mcp), "flagged login token must carry the mcp claim")
	require.True(t, mcp)
}

func TestSeedAdmin_LoginWithoutFlagCarriesNoMCP(t *testing.T) {
	svc, _ := setupUserService(t)
	registerTestUser(t, svc, "alice", "alice@example.com")

	login, err := svc.Login(context.Background(), "alice", "Str0ng!Pass")
	require.NoError(t, err)

	tok, err := jwtauth.VerifyToken(svc.auth, login.Token)
	require.NoError(t, err)
	var mcp bool
	require.Error(t, tok.Get("mcp", &mcp), "unflagged login token must NOT carry the mcp claim")
}

func TestSeedAdmin_DuplicateReturnsWrappedExists(t *testing.T) {
	svc, _ := setupUserService(t)
	_, err := svc.SeedAdmin(context.Background(), "admin@localhost", "weak")
	require.NoError(t, err)

	_, err = svc.SeedAdmin(context.Background(), "admin@localhost", "weak2")
	require.ErrorIs(t, err, ErrUserExists)
}

// The differ-from-current check (ErrSamePassword) used to be declared and
// mapped in handlers but never returned by the service — pin both call sites.
func TestChangePassword_SamePasswordRejected(t *testing.T) {
	svc, _ := setupUserService(t)
	registerTestUser(t, svc, "alice", "alice@example.com")

	err := svc.ChangePassword(context.Background(), 1, "Str0ng!Pass", "Str0ng!Pass")
	require.ErrorIs(t, err, ErrSamePassword)
}

func TestForceChangePassword_SamePasswordRejected(t *testing.T) {
	svc, _ := setupUserService(t)
	_, err := svc.SeedAdmin(context.Background(), "admin@localhost", "weak")
	require.NoError(t, err)

	require.NoError(t, svc.ForceChangePassword(context.Background(), 1, "Str0ng!Pass2"))
	err = svc.ForceChangePassword(context.Background(), 1, "Str0ng!Pass2")
	require.ErrorIs(t, err, ErrSamePassword)
}

// Self-service changes must stamp password_changed_at (previously only the
// force/admin paths did — the column stayed NULL for users who changed their
// password from the settings page).
func TestChangePassword_StampsPasswordChangedAt(t *testing.T) {
	svc, sqlDB := setupUserService(t)
	registerTestUser(t, svc, "alice", "alice@example.com")

	var before sql.NullString
	err := sqlDB.QueryRow("SELECT password_changed_at FROM users WHERE id = 1").Scan(&before)
	require.NoError(t, err)
	require.False(t, before.Valid, "register must not stamp password_changed_at")

	require.NoError(t, svc.ChangePassword(context.Background(), 1, "Str0ng!Pass", "Str0ng!Pass2"))

	var after sql.NullString
	err = sqlDB.QueryRow("SELECT password_changed_at FROM users WHERE id = 1").Scan(&after)
	require.NoError(t, err)
	require.True(t, after.Valid, "self-service change must stamp password_changed_at")
}

// The installer's default is an EMPTY initial_admin_password: the admin is
// seeded password-less and the browser setup flow (POST /auth/setup) creates
// the credential. Pin the full arc — pending detection, login impossible
// (distinct sentinel, no failure-counter side effect), setup completes with a
// policy-compliant password and lands a fresh UNGATED token, and the one-shot
// window closes for good afterwards.
func TestSetupFlow_EmptyPasswordSeedArc(t *testing.T) {
	svc, sqlDB := setupUserService(t)
	ctx := context.Background()

	resp, err := svc.SeedAdmin(ctx, "admin@localhost", "")
	require.NoError(t, err)
	require.True(t, resp.MustChangePassword)

	require.True(t, svc.SetupPending(ctx), "empty-hash seed must report setup pending")

	// Login against a pending account returns the sentinel — NOT invalid
	// credentials, and it must not tick the failure counter.
	_, err = svc.Login(ctx, "admin", "guess")
	require.ErrorIs(t, err, ErrSetupPending)
	var attempts int
	require.NoError(t, sqlDB.QueryRow("SELECT failed_login_attempts FROM users WHERE username = 'admin'").Scan(&attempts))
	require.Zero(t, attempts, "pending-setup login attempts must not count as failures")

	// Setup validates against the effective policy.
	_, err = svc.CompleteSetup(ctx, "weak")
	require.ErrorIs(t, err, ErrWeakPassword)

	login, err := svc.CompleteSetup(ctx, "Str0ng!Pass")
	require.NoError(t, err)
	require.Equal(t, "admin", login.User.Username)
	require.False(t, login.User.MustChangePassword)
	require.NotEmpty(t, login.Token)

	// The token the SPA lands with must NOT carry the mcp gate — the password
	// was just chosen by the operator, there is nothing left to force.
	tok, err := jwtauth.VerifyToken(svc.auth, login.Token)
	require.NoError(t, err)
	var mcp bool
	require.Error(t, tok.Get("mcp", &mcp), "setup-completion token must not carry the mcp claim")

	// Login with the chosen password now works.
	after, err := svc.Login(ctx, "admin", "Str0ng!Pass")
	require.NoError(t, err)
	require.False(t, after.User.MustChangePassword)

	// One-shot: the setup window closed.
	require.False(t, svc.SetupPending(ctx))
	_, err = svc.CompleteSetup(ctx, "Another!Pass1")
	require.ErrorIs(t, err, ErrNoPendingSetup)
}

// A pending-setup admin and an ordinary user coexist: the sentinel only fires
// for the empty-hash account.
func TestSetupFlow_SentinelOnlyForPendingAccount(t *testing.T) {
	svc, _ := setupUserService(t)
	ctx := context.Background()
	registerTestUser(t, svc, "alice", "alice@example.com")
	_, err := svc.SeedAdmin(ctx, "admin@localhost", "")
	require.NoError(t, err)

	_, err = svc.Login(ctx, "alice", "wrong")
	require.ErrorIs(t, err, ErrInvalidCredentials, "ordinary users keep normal login semantics")
	_, err = svc.Login(ctx, "alice", "Str0ng!Pass")
	require.NoError(t, err)
}
