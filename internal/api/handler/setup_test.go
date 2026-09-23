// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// End-to-end first-run setup: the installer seeds the admin with an EMPTY
// password (auth.initial_admin_password unset). The login page polls the
// public setup-status endpoint, login attempts return the distinct 409
// setup_required code, POST /auth/setup creates the password (policy-checked,
// single-use), and the response carries a fresh ungated token + cookie so the
// SPA enters the app directly.
func TestAuth_FirstRunSetupFlow(t *testing.T) {
	server, db := setupTestServer(t)

	// Seed exactly like SeedAdmin(ctx, email, "") does: empty hash, flagged.
	_, err := db.Exec(
		"INSERT INTO users (username, email, password_hash, role, must_change_password) VALUES (?, ?, ?, ?, 1)",
		"admin", "admin@test.com", "", "admin",
	)
	require.NoError(t, err)

	// Public setup-status: required=true, no auth needed.
	statusResp, err := http.Get(server.URL + "/api/v1/auth/setup-status")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, statusResp.StatusCode)
	var status map[string]any
	decodeJSON(t, statusResp, &status)
	require.Equal(t, true, status["required"])

	// Login against the password-less account: 409 with the machine-readable
	// code the SPA switches on, NOT a generic 401.
	loginResp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json",
		bytes.NewBufferString(`{"username":"admin","password":"whatever"}`))
	require.NoError(t, err)
	defer loginResp.Body.Close()
	require.Equal(t, http.StatusConflict, loginResp.StatusCode)
	var loginBody map[string]any
	decodeJSON(t, loginResp, &loginBody)
	require.Equal(t, "setup_required", loginBody["error"])

	// Setup enforces the effective password policy.
	weakResp, err := http.Post(server.URL+"/api/v1/auth/setup", "application/json",
		bytes.NewBufferString(`{"new_password":"weak"}`))
	require.NoError(t, err)
	weakResp.Body.Close()
	require.Equal(t, http.StatusBadRequest, weakResp.StatusCode)

	// Complete setup, same response shape as login (token + user + cookie).
	setupResp, err := http.Post(server.URL+"/api/v1/auth/setup", "application/json",
		bytes.NewBufferString(`{"new_password":"NewP@ssw0rd2"}`))
	require.NoError(t, err)
	defer setupResp.Body.Close()
	require.Equal(t, http.StatusOK, setupResp.StatusCode)

	var setupBody map[string]any
	decodeJSON(t, setupResp, &setupBody)
	token, _ := setupBody["token"].(string)
	require.NotEmpty(t, token, "setup must return a session token")
	setupUser, _ := setupBody["user"].(map[string]any)
	require.NotNil(t, setupUser)
	require.Equal(t, "admin", setupUser["username"])
	require.Equal(t, false, setupUser["must_change_password"])

	var cookieSeen bool
	for _, c := range setupResp.Cookies() {
		if c.Name == "token" && c.Value == token {
			cookieSeen = true
		}
	}
	require.True(t, cookieSeen, "setup must set the auth cookie like login does")

	// The setup token is a normal session (no mcp gate).
	profileReq, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/auth/profile", nil)
	require.NoError(t, err)
	profileReq.Header.Set("Authorization", "Bearer "+token)
	profileResp, err := http.DefaultClient.Do(profileReq)
	require.NoError(t, err)
	defer profileResp.Body.Close()
	require.Equal(t, http.StatusOK, profileResp.StatusCode)

	// The window closed: status flips to false and a second setup 409s.
	statusResp2, err := http.Get(server.URL + "/api/v1/auth/setup-status")
	require.NoError(t, err)
	var status2 map[string]any
	decodeJSON(t, statusResp2, &status2)
	require.Equal(t, false, status2["required"])

	againResp, err := http.Post(server.URL+"/api/v1/auth/setup", "application/json",
		bytes.NewBufferString(`{"new_password":"Another!Pass1"}`))
	require.NoError(t, err)
	againResp.Body.Close()
	require.Equal(t, http.StatusConflict, againResp.StatusCode)

	// Ordinary login with the created password now works.
	token2 := loginAsAdmin2(t, server, "NewP@ssw0rd2")
	require.NotEmpty(t, token2)
}

// On a deployment whose admin already has a password, setup-status answers
// false and the login form renders, the setup screen never appears.
func TestAuth_SetupStatusFalseWhenPasswordExists(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	statusResp, err := http.Get(server.URL + "/api/v1/auth/setup-status")
	require.NoError(t, err)
	var status map[string]any
	decodeJSON(t, statusResp, &status)
	require.Equal(t, false, status["required"])
}

// loginAsAdmin2 logs the seeded admin in with a custom password (the setup
// flow changed it from the fixture default).
func loginAsAdmin2(t *testing.T, server *httptest.Server, password string) string {
	t.Helper()
	return loginAs(t, server, "admin", password)
}
