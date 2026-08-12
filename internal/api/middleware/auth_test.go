// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/service"
)

// These tests pin the JWT Authenticator (#171). It is the security gate every
// browser/user route passes through: a VALID token injects user_id + role into
// the request context (downstream RBAC then authorizes); a missing/invalid/
// expired/revoked token is passed through ANONYMOUSLY (GetUserFromContext returns
// !ok), and RequireAuth/RequireAdmin turn that into 401. A regression here is an
// auth-bypass hole, so the anonymous-on-failure contract is the load-bearing
// invariant to lock.

// authProbe wraps Authenticator around a handler that echoes the resolved
// identity ("uid=N role=R") or "anon" when no user is in context.
func authProbe() http.Handler {
	return middleware.Authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, role, ok := middleware.GetUserFromContext(r)
		if !ok {
			_, _ = w.Write([]byte("anon"))
			return
		}
		fmt.Fprintf(w, "uid=%d role=%s", uid, role)
	}))
}

func reqWithBearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func reqWithCookie(name, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		r.AddCookie(&http.Cookie{Name: name, Value: token})
	}
	return r
}

// useJWTAuth installs a fresh JWT authenticator for the test and returns a
// cleanup restoring prior behavior. The Authenticator reads a package global.
func useJWTAuth(t *testing.T) {
	t.Helper()
	middleware.SetJWTAuth("test-secret-please-rotate")
}

func issueToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	_, s, err := middleware.GetJWTAuth().Encode(claims)
	require.NoError(t, err)
	return s
}

func TestAuthenticator_ValidBearerTokenAuthenticates(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 42.0, "role": "user"})

	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, reqWithBearer(tok))

	require.Equal(t, "uid=42 role=user", rec.Body.String())
}

func TestAuthenticator_CookieTokenWorks(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{"user_id": 7.0, "role": "admin"})

	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, reqWithCookie("token", tok))

	require.Equal(t, "uid=7 role=admin", rec.Body.String())
}

// TestAuthenticator_CookiePreferredOverBearer pins extractToken's cookie-first
// precedence: when both are present, the cookie wins. (The reverse — valid
// bearer shadowed by an invalid cookie — is the auth-bypass case this guards.)
func TestAuthenticator_CookiePreferredOverBearer(t *testing.T) {
	useJWTAuth(t)
	valid := issueToken(t, map[string]any{"user_id": 1.0, "role": "user"})

	// Cookie carries the valid token; bearer carries garbage. Cookie wins → authed.
	rec := httptest.NewRecorder()
	r := reqWithCookie("token", valid)
	r.Header.Set("Authorization", "Bearer not.a.jwt")
	authProbe().ServeHTTP(rec, r)
	require.Equal(t, "uid=1 role=user", rec.Body.String(), "cookie token must take precedence")
}

func TestAuthenticator_MissingTokenIsAnonymous(t *testing.T) {
	useJWTAuth(t)
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, reqWithBearer(""))
	require.Equal(t, "anon", rec.Body.String())
}

func TestAuthenticator_GarbageTokenIsAnonymous(t *testing.T) {
	useJWTAuth(t)
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, reqWithBearer("garbage.not-a-jwt"))
	require.Equal(t, "anon", rec.Body.String())
}

func TestAuthenticator_ExpiredTokenIsAnonymous(t *testing.T) {
	useJWTAuth(t)
	tok := issueToken(t, map[string]any{
		"user_id": 1.0,
		"role":    "user",
		"exp":     time.Now().Add(-time.Hour).Unix(), // expired
	})
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, reqWithBearer(tok))
	require.Equal(t, "anon", rec.Body.String(), "expired token must not authenticate")
}

func TestAuthenticator_BlacklistedTokenIsAnonymous(t *testing.T) {
	useJWTAuth(t)
	const jti = "revoked-session-1"
	tok := issueToken(t, map[string]any{"user_id": 1.0, "role": "user", "jti": jti})

	bl := service.NewTokenBlacklist()
	bl.Add(jti, time.Hour)
	middleware.SetTokenBlacklist(bl)
	t.Cleanup(func() { middleware.SetTokenBlacklist(nil) }) // don't leak into other tests

	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, reqWithBearer(tok))
	require.Equal(t, "anon", rec.Body.String(), "a blacklisted (revoked) token must not authenticate")
}

// TestAuthenticator_MalformedAuthHeaderIsAnonymous pins extractToken's
// "Bearer <token>" parsing: a non-Bearer scheme (e.g. "Basic ...") yields no
// token → anonymous, never a crash or accidental parse.
func TestAuthenticator_MalformedAuthHeaderIsAnonymous(t *testing.T) {
	useJWTAuth(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // not a Bearer
	rec := httptest.NewRecorder()
	authProbe().ServeHTTP(rec, r)
	require.Equal(t, "anon", rec.Body.String())
}

func TestGetUserFromContext_EmptyContextNotOk(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, _, ok := middleware.GetUserFromContext(r)
	require.False(t, ok)
}
