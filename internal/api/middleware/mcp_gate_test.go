// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// The must-change-password gate: a token minted while the user's flag was set
// carries mcp=true and must be locked out of everything except the
// change-survival allowlist (force-password, profile GET, 2FA management).
// This is the server-side enforcement of the first-login flow — a regression
// here turns the forced change back into an SPA-only courtesy.

func TestAuthenticator_MCPBlocksOtherEndpoints(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 1.0, "role": "admin", "mcp": true})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, r)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "password_change_required")
}

func TestAuthenticator_MCPAllowlist(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 1.0, "role": "admin", "mcp": true})

	for _, target := range []struct{ method, path string }{
		{http.MethodPut, "/api/v1/auth/force-password"},
		{http.MethodGet, "/api/v1/auth/profile"},
		{http.MethodGet, "/api/v1/auth/2fa/status"},
		{http.MethodPost, "/api/v1/auth/2fa/setup"},
	} {
		r := httptest.NewRequest(target.method, target.path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		authProbe().ServeHTTP(rec, r)

		require.Equal(t, http.StatusOK, rec.Code, "allowlisted %s %s must pass", target.method, target.path)
		require.Contains(t, rec.Body.String(), "uid=1", "allowlisted %s %s must reach the handler", target.method, target.path)
	}
}

// Profile PUT is a mutation outside the change flow — still gated.
func TestAuthenticator_MCPBlocksProfilePut(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 1.0, "role": "admin", "mcp": true})

	r := httptest.NewRequest(http.MethodPut, "/api/v1/auth/profile", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, r)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestAuthenticator_TokenWithoutMCPPasses(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 2.0, "role": "user"})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "uid=2 role=user", rec.Body.String())
}

// The gate must live in the Authenticator only — anonymous requests (no
// token) are public routes' business and never see it.
func TestAuthenticator_MCPGateNoTokenUnaffected(t *testing.T) {
	useJWTAuth(t)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "anon", rec.Body.String())
}
