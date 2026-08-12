// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/middleware"
)

// These tests pin RequireAuth / RequireAdmin (#171) — the authorization gates
// that turn the Authenticator's context (or lack of it) into 401/403. They wrap
// Authenticator, so each is exercised end-to-end with a real signed JWT:
//   - RequireAuth:  valid user → next;  no/invalid token → 401.
//   - RequireAdmin: admin → next;  non-admin → 403;  no/invalid token → 401.
// A regression here is a privilege-escalation or auth-bypass hole.

// okHandler is the protected downstream handler; writing 200 "ok" proves the
// gate passed the request through.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestRequireAuth_ValidTokenPasses(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 1.0, "role": "user"})

	rec := httptest.NewRecorder()
	middleware.RequireAuth(okHandler()).ServeHTTP(rec, reqWithBearer(tok))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

func TestRequireAuth_MissingTokenReturns401(t *testing.T) {
	useJWTAuth(t)
	rec := httptest.NewRecorder()
	middleware.RequireAuth(okHandler()).ServeHTTP(rec, reqWithBearer(""))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireAuth_InvalidTokenReturns401(t *testing.T) {
	useJWTAuth(t)
	rec := httptest.NewRecorder()
	middleware.RequireAuth(okHandler()).ServeHTTP(rec, reqWithBearer("garbage"))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireAdmin_AdminPasses(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 1.0, "role": "admin"})

	rec := httptest.NewRecorder()
	middleware.RequireAdmin(okHandler()).ServeHTTP(rec, reqWithBearer(tok))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

// TestRequireAdmin_NonAdminReturns403 pins the privilege boundary: an
// authenticated but non-admin user is rejected with 403 (not 401 — they ARE
// authenticated, just not authorized). This is the privilege-escalation guard.
func TestRequireAdmin_NonAdminReturns403(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 2.0, "role": "user"})

	rec := httptest.NewRecorder()
	middleware.RequireAdmin(okHandler()).ServeHTTP(rec, reqWithBearer(tok))
	require.Equal(t, http.StatusForbidden, rec.Code, "non-admin must get 403, not pass-through")
}

func TestRequireAdmin_MissingTokenReturns401(t *testing.T) {
	useJWTAuth(t)
	rec := httptest.NewRecorder()
	middleware.RequireAdmin(okHandler()).ServeHTTP(rec, reqWithBearer(""))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
