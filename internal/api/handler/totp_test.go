// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// These tests pin the 2FA (TOTP) HTTP handler layer (#171). The TOTP *service*
// (algorithm + storage) is covered by service/totp_test.go; the thin handler
// layer (error→status mapping) was untested. The load-bearing security invariant
// is the BYPASS GUARD: Verify with a wrong code MUST be rejected (422), never
// accepted — a regression here is a 2FA bypass = account takeover.

// setupAndEnable2FA seeds a user, logs in, runs the setup→enable flow with a
// valid current code, and returns the secret + the user's id + login token.
func setupAndEnable2FA(t *testing.T, server *httptest.Server, db *sql.DB, username, password string) (secret string, userID int64, token string) {
	t.Helper()
	userID = insertTestUser(t, db, username, username+"@test.com", "user", password)
	token = loginAs(t, server, username, password)

	// Setup → returns the TOTP secret + QR URL.
	resp := authPost(t, server.URL+"/api/v1/auth/2fa/setup", token, `{}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var setup struct {
		Secret string `json:"secret"`
	}
	decodeJSON(t, resp, &setup)
	require.NotEmpty(t, setup.Secret, "setup must return a secret")

	// Enable with a valid current code derived from that secret.
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, err)
	resp = authPost(t, server.URL+"/api/v1/auth/2fa/enable", token, `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "enable with a valid code must succeed")
	return setup.Secret, userID, token
}

func Test2FA_SetupReturnsSecret(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "ivan", "ivan@test.com", "user", "Ivan@2026")
	token := loginAs(t, server, "ivan", "Ivan@2026")

	resp := authPost(t, server.URL+"/api/v1/auth/2fa/setup", token, `{}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var setup struct {
		Secret string `json:"secret"`
	}
	decodeJSON(t, resp, &setup)
	require.NotEmpty(t, setup.Secret)
}

func Test2FA_EnableWithValidCode_StatusEnabled(t *testing.T) {
	server, db := setupTestServer(t)
	_, _, token := setupAndEnable2FA(t, server, db, "judy", "Judy@2026")

	resp := authGet(t, server.URL+"/api/v1/auth/2fa/status", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var status struct {
		Enabled bool `json:"enabled"`
	}
	decodeJSON(t, resp, &status)
	require.True(t, status.Enabled, "status must report 2FA enabled after a valid enable")
}

// Test2FA_EnableWithInvalidCode_Rejected: a wrong code cannot enable 2FA (the
// user must prove possession of the authenticator secret first).
func Test2FA_EnableWithInvalidCode_Rejected(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "kate", "kate@test.com", "user", "Kate@2026")
	token := loginAs(t, server, "kate", "Kate@2026")

	authPost(t, server.URL+"/api/v1/auth/2fa/setup", token, `{}`) // setup first
	resp := authPost(t, server.URL+"/api/v1/auth/2fa/enable", token, `{"code":"000000"}`)
	require.NotEqual(t, http.StatusOK, resp.StatusCode, "an invalid code must not enable 2FA")
}

// Test2FA_VerifyValidCode_ReturnsToken: the public 2FA login step, given a valid
// code for an enabled user, issues a session token (completes 2FA login).
func Test2FA_VerifyValidCode_ReturnsToken(t *testing.T) {
	server, db := setupTestServer(t)
	secret, userID, _ := setupAndEnable2FA(t, server, db, "liam", "Liam@2026")

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	resp := authPost(t, server.URL+"/api/v1/auth/2fa/verify", "",
		`{"user_id":`+itoaInt64(userID)+`,"code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	decodeJSON(t, resp, &body)
	require.NotEmpty(t, body["token"], "a valid 2FA verify must issue a session token")
}

// Test2FA_VerifyInvalidCode_Rejected is the BYPASS GUARD: a wrong code at the
// 2FA login step MUST be rejected (422), never accepted. This is the single
// most security-critical assertion in the 2FA surface.
func Test2FA_VerifyInvalidCode_Rejected(t *testing.T) {
	server, db := setupTestServer(t)
	_, userID, _ := setupAndEnable2FA(t, server, db, "mike", "Mike@2026")

	resp := authPost(t, server.URL+"/api/v1/auth/2fa/verify", "",
		`{"user_id":`+itoaInt64(userID)+`,"code":"000000"}`)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode,
		"a wrong 2FA code must be rejected with 422 — accepting it is a 2FA bypass")
	// And critically, no token is issued.
	var body map[string]any
	decodeJSON(t, resp, &body)
	require.Empty(t, body["token"], "no session token on a rejected 2FA verify")
}

// itoaInt64 formats an int64 for the verify request body.
func itoaInt64(n int64) string { return strconv.FormatInt(n, 10) }
