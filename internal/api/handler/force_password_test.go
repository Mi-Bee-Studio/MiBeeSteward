// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// End-to-end first-login forced change: a flagged admin logs in (token gated
// by the mcp claim), is 403'd on a normal endpoint, completes the forced
// change, and receives a FRESH ungated token + cookie in the force-password
// response.
func TestAuth_ForcedPasswordChangeFlow(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	// Flag the admin exactly like the startup seeder does.
	_, err := db.Exec("UPDATE users SET must_change_password = 1 WHERE username = 'admin'")
	require.NoError(t, err)

	// Login while flagged.
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json",
		bytes.NewBufferString(`{"username":"admin","password":"admin123"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var loginResult map[string]any
	decodeJSON(t, resp, &loginResult)
	gatedToken, _ := loginResult["token"].(string)
	require.NotEmpty(t, gatedToken, "login must return a token")

	var gatedUser map[string]any
	gatedUser, _ = loginResult["user"].(map[string]any)
	require.NotNil(t, gatedUser)
	require.Equal(t, true, gatedUser["must_change_password"])

	// The gated token is refused on a normal endpoint (server-side mcp gate).
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/devices", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+gatedToken)
	gatedResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	gatedResp.Body.Close()
	require.Equal(t, http.StatusForbidden, gatedResp.StatusCode)

	// Complete the forced change, must yield a NEW token + cookie.
	forceResp, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/auth/force-password", bytes.NewBufferString(`{"new_password":"NewP@ssw0rd2"}`))
	require.NoError(t, err)
	forceResp.Header.Set("Authorization", "Bearer "+gatedToken)
	forceResp.Header.Set("Content-Type", "application/json")
	forceResult, err := http.DefaultClient.Do(forceResp)
	require.NoError(t, err)
	defer forceResult.Body.Close()
	require.Equal(t, http.StatusOK, forceResult.StatusCode)

	var forceBody map[string]any
	decodeJSON(t, forceResult, &forceBody)
	newToken, _ := forceBody["token"].(string)
	require.NotEmpty(t, newToken, "force-password must return a fresh ungated token")
	require.NotEqual(t, gatedToken, newToken)

	var cookieSeen bool
	for _, c := range forceResult.Cookies() {
		if c.Name == "token" && c.Value == newToken {
			cookieSeen = true
		}
	}
	require.True(t, cookieSeen, "force-password must rotate the auth cookie to the new token")

	// The fresh token is ungated: a normal endpoint answers 200.
	req2, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/auth/profile", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+newToken)
	ungatedResp, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer ungatedResp.Body.Close()
	require.Equal(t, http.StatusOK, ungatedResp.StatusCode)

	var profile map[string]any
	decodeJSON(t, ungatedResp, &profile)
	require.Equal(t, "admin", profile["username"])

	// And the flagged flag is gone on re-login with the new password.
	relogin, err := http.Post(server.URL+"/api/v1/auth/login", "application/json",
		bytes.NewBufferString(`{"username":"admin","password":"NewP@ssw0rd2"}`))
	require.NoError(t, err)
	defer relogin.Body.Close()
	var reloginResult map[string]any
	decodeJSON(t, relogin, &reloginResult)
	reloginUser, _ := reloginResult["user"].(map[string]any)
	require.NotNil(t, reloginUser)
	require.Equal(t, false, reloginUser["must_change_password"])
}

// The forced change cannot be completed with the SAME password (bootstrap
// credential or previously-set), ErrSamePassword is now actually returned.
func TestAuth_ForcePasswordSamePasswordRejected(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	token := loginAsAdmin(t, server)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/auth/force-password",
		bytes.NewBufferString(`{"new_password":"admin123"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Contains(t, body["error"], "different")
}
