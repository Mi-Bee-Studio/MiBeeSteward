// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// asUser injects the middleware's user/role context values so protected
// handlers can be driven directly.
func asUser(r *http.Request, userID int64, role string) *http.Request {
	ctx := context.WithValue(r.Context(), domain.ContextKeyUserID, userID)
	ctx = context.WithValue(ctx, domain.ContextKeyRole, role)
	return r.WithContext(ctx)
}

// TestTOTPHandler_DeadDB_StorageArms drives the storage-failure arms with a
// real (injected) user context over a dead handle: setup profile fetch,
// setup secret store, enable store, and disable user-lookup all return 500s.
func TestTOTPHandler_DeadDB_StorageArms(t *testing.T) {
	conn := closedTestDB(t)
	audit := service.NewAuditRepository(conn)
	userSvc := service.NewUserService(conn, "test-secret-key-for-tests-32-bytes!!", 0, config.PasswordPolicyConfig{})
	h := NewTOTPHandler(service.NewTOTPService(conn, audit), userSvc, &config.Config{}, audit)

	r := httptest.NewRecorder()
	h.Setup(r, asUser(httptest.NewRequest(http.MethodPost, "/api/v1/auth/2fa/setup", nil), 1, "user"))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	h.Enable(r, asUser(reqWithBodyParams(http.MethodPost, "/api/v1/auth/2fa/enable",
		`{"code":"123456"}`, nil), 1, "user"))
	require.Equal(t, http.StatusInternalServerError, r.Code)

	r = httptest.NewRecorder()
	h.Disable(r, asUser(reqWithBodyParams(http.MethodPost, "/api/v1/auth/2fa/disable",
		`{"password":"x"}`, nil), 1, "user"))
	require.Equal(t, http.StatusInternalServerError, r.Code)
}

// TestTOTPHandler_DisableDeletedUser404: a user whose token still parses but
// whose row is gone gets the not-found mapping on disable.
func TestTOTPHandler_DisableDeletedUser404(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)
	audit := service.NewAuditRepository(conn)
	userSvc := service.NewUserService(conn, "test-secret-key-for-tests-32-bytes!!", 0, config.PasswordPolicyConfig{})
	h := NewTOTPHandler(service.NewTOTPService(conn, audit), userSvc, &config.Config{}, audit)

	// User 99 does not exist; the disable path maps ErrUserNotFound → 404
	// (the service returns it once bcrypt comparison fails on the empty
	// stored hash, reached here because the user row is absent).
	r := httptest.NewRecorder()
	h.Disable(r, asUser(reqWithBodyParams(http.MethodPost, "/api/v1/auth/2fa/disable",
		`{"password":"whatever1"}`, nil), 99, "user"))
	// The service's not-found mapping only fires on the named error; over a
	// live handle with a missing row it lands there via GetUser's ErrNoRows.
	require.Equal(t, http.StatusNotFound, r.Code)
	_ = queries
	_ = sql.ErrNoRows
}
