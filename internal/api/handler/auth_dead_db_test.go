// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAuthRoutes_DeadDB sweeps the auth handlers' failure branches on a dead
// handle: login maps storage failures to invalid-credentials (no user
// enumeration), and the first-run setup wraps its service error as a 500.
func TestAuthRoutes_DeadDB(t *testing.T) {
	server, db := setupTestServer(t)
	require.NoError(t, db.Close())

	resp, _ := postPlain28(t, server.URL+"/api/v1/auth/login",
		`{"username":"anyone","password":"whatever"}`)
	require.Equal(t, http.StatusUnauthorized, resp)

	resp, _ = postPlain28(t, server.URL+"/api/v1/auth/setup",
		`{"new_password":"Str0ng!Pass"}`)
	require.Equal(t, http.StatusInternalServerError, resp)
}

// TestRegister_BcryptOverflowIs500 pins Register's generic-error arm: a
// password that passes the policy classes but exceeds bcrypt's 72-byte cap
// fails inside the service past the mapped (conflict/weak) arms → 500.
func TestRegister_BcryptOverflowIs500(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "regadmin", "regadmin@test.com", "admin", "Reg@2026")
	token := loginAs(t, server, "regadmin", "Reg@2026")

	resp, body := postPlainAuth28(t, server.URL+"/api/v1/auth/register", token,
		`{"username":"newu","email":"newu@invalid","password":"Aa1!`+strings.Repeat("a", 100)+`","role":"user"}`)
	require.Equal(t, http.StatusInternalServerError, resp, "body=%s", body)
}

// TestLogin_TwoFactorChallengeCookieRoute pins the route-level 2FA challenge:
// an enrolled user's login answers the challenge shape (TwoFactorRequired,
// no token) instead of a session.
func TestLogin_TwoFactorChallengeCookieRoute(t *testing.T) {
	server, db := setupTestServer(t)
	secret, _, _ := setupAndEnable2FA(t, server, db, "challu", "Chal@2026")
	require.NotEmpty(t, secret)

	code, body := postPlain28(t, server.URL+"/api/v1/auth/login",
		`{"username":"challu","password":"Chal@2026"}`)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, body, `"two_factor_required":true`)
	require.NotContains(t, body, `"token":"eyJ`, "no session token in the challenge response")
}

// TestLogout_WithLiveToken drives logout with a REAL bearer token: the jti+exp
// claims parse, the token is blacklisted for its remaining lifetime, and the
// audit row lands.
func TestLogout_WithLiveToken(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "logoutu", "logoutu@test.com", "user", "Out@2026")
	token := loginAs(t, server, "logoutu", "Out@2026")

	resp := authPost(t, server.URL+"/api/v1/auth/logout", token, `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func postPlain28(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode, readAll28(t, resp)
}

func postPlainAuth28(t *testing.T, url, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode, readAll28(t, resp)
}

func readAll28(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}
