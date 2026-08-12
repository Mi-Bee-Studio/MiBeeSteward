// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler_test

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// These tests extend the user/auth handler coverage (#171). handler_test.go
// already covers Login (success/invalid/missing) + Profile; these pin the
// UNTESTED security-critical user-management paths: admin-gated user creation,
// self password change (with old-password verification), admin password reset,
// and the ListUsers privilege boundary. A regression in any is a privilege or
// account-takeover risk.

// insertTestUser seeds a user row directly with the given role + password,
// bypassing the service password policy so test fixtures aren't gated by
// strength rules. Returns the new row id.
func insertTestUser(t *testing.T, db *sql.DB, username, email, role, password string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	res, err := db.Exec(
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
		username, email, string(hash), role,
	)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// loginStatus attempts a login and returns the HTTP status (no assertion), for
// verifying a credential pair succeeds OR fails.
func loginStatus(t *testing.T, server *httptest.Server, username, password string) int {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

// --- Register (admin-only) ---

func TestUserRegister_AdminCreatesUserThenLogin(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	admin := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/auth/register", admin,
		`{"username":"alice","email":"alice@test.com","password":"Alice@2026","role":"user"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// The new user can authenticate with the admin-set password.
	token := loginAs(t, server, "alice", "Alice@2026")
	require.NotEmpty(t, token)
}

func TestUserRegister_DuplicateName_Conflict(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "bob", "bob@test.com", "user", "Bob@2026")
	insertTestAdmin(t, db)
	admin := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/auth/register", admin,
		`{"username":"bob","email":"bob2@test.com","password":"Bob@2026","role":"user"}`)
	require.Equal(t, http.StatusConflict, resp.StatusCode, "duplicate username → 409")
}

// --- ChangePassword (self, old-password verified) ---

func TestUserChangePassword_Success(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "carol", "carol@test.com", "user", "Carol@2026")
	token := loginAs(t, server, "carol", "Carol@2026")

	resp := authPut(t, server.URL+"/api/v1/auth/password", token,
		`{"old_password":"Carol@2026","new_password":"Carol@2027!"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// New password authenticates; the old one no longer does.
	require.NotEmpty(t, loginAs(t, server, "carol", "Carol@2027!"))
	require.Equal(t, http.StatusUnauthorized,
		loginStatus(t, server, "carol", "Carol@2026"), "old password must stop working")
}

func TestUserChangePassword_WrongOldPassword(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "dave", "dave@test.com", "user", "Dave@2026")
	token := loginAs(t, server, "dave", "Dave@2026")

	resp := authPut(t, server.URL+"/api/v1/auth/password", token,
		`{"old_password":"totally-wrong","new_password":"Dave@2027!"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "wrong old password → 400")

	// Original password still works (the change was rejected).
	require.NotEmpty(t, loginAs(t, server, "dave", "Dave@2026"))
}

// --- ListUsers privilege boundary ---

func TestListUsers_RequiresAdmin(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestUser(t, db, "eve", "eve@test.com", "user", "Eve@2026")
	insertTestAdmin(t, db)
	userToken := loginAs(t, server, "eve", "Eve@2026")
	adminToken := loginAsAdmin(t, server)

	// A regular user is rejected by the RequireAdmin gate.
	resp := authGet(t, server.URL+"/api/v1/users", userToken)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "non-admin listing users → 403")

	// An admin gets the list.
	resp = authGet(t, server.URL+"/api/v1/users", adminToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- AdminResetPassword (admin resets another user) ---

func TestAdminResetPassword_SuccessThenLogin(t *testing.T) {
	server, db := setupTestServer(t)
	frankID := insertTestUser(t, db, "frank", "frank@test.com", "user", "Frank@2026")
	insertTestAdmin(t, db)
	admin := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/users/"+strconv.FormatInt(frankID, 10)+"/reset-password", admin,
		`{"new_password":"Frank@2027!"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The target user can now log in with the admin-reset password.
	require.NotEmpty(t, loginAs(t, server, "frank", "Frank@2027!"))
	// ... and the OLD password no longer works.
	require.Equal(t, http.StatusUnauthorized,
		loginStatus(t, server, "frank", "Frank@2026"))
}

func TestAdminResetPassword_NotFound(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	admin := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/users/99999/reset-password", admin,
		`{"new_password":"Any@2026"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "resetting a non-existent user → 404")
}
