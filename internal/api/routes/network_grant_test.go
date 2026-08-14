// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the network-grant management API (#138 Phase 3): admin can
// create/list/delete grants; a duplicate is 409; a non-admin is 403; deleting
// invalidates the scope so the user's visibility changes immediately.

func TestNetworkGrants_AdminCRUD(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, false) // no grants seeded
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	admin := tokenForUser(t, cfg.Auth.JWTSecret, 2, "admin") // user_id=2 admin
	viewer := tokenForUser(t, cfg.Auth.JWTSecret, 1, "viewer")

	// Non-admin cannot create a grant.
	rec := postJSON(t, handler, "/api/v1/network-grants", `{"user_id":1,"network_id":1}`, viewer)
	require.Equal(t, http.StatusForbidden, rec.Code, "viewer must be 403 on grant create")

	// Admin creates a grant (user 1 → network 1).
	rec = postJSON(t, handler, "/api/v1/network-grants", `{"user_id":1,"network_id":1}`, admin)
	require.Equal(t, http.StatusCreated, rec.Code, "body=%s", rec.Body.String())
	var created struct {
		ID int64 `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotZero(t, created.ID)

	// Duplicate → 409.
	rec = postJSON(t, handler, "/api/v1/network-grants", `{"user_id":1,"network_id":1}`, admin)
	require.Equal(t, http.StatusConflict, rec.Code)

	// Unknown user/network → 400.
	rec = postJSON(t, handler, "/api/v1/network-grants", `{"user_id":999,"network_id":1}`, admin)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = postJSON(t, handler, "/api/v1/network-grants", `{"user_id":1,"network_id":999}`, admin)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// List all grants includes the created one.
	rec = getAuth(handler, "/api/v1/network-grants", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		Grants []struct {
			UserID    int64  `json:"user_id"`
			NetworkID int64  `json:"network_id"`
			Username  string `json:"username"`
		} `json:"grants"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Equal(t, 1, list.Total)
	require.Equal(t, int64(1), list.Grants[0].UserID)
	require.Equal(t, int64(1), list.Grants[0].NetworkID)
	require.Equal(t, "viewer1", list.Grants[0].Username, "list should join username")

	// Per-user list.
	rec = getAuth(handler, "/api/v1/users/1/network-grants", admin)
	require.Equal(t, http.StatusOK, rec.Code)

	// Grant now takes effect: viewer (user 1) in closed mode sees only network 1.
	rec = getAuth(handler, "/api/v1/devices", viewer)
	require.Equal(t, http.StatusOK, rec.Code)
	var devs deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &devs))
	require.Equal(t, 1, devs.Total, "viewer now scoped to network 1 only")

	// Delete the grant → 204.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/network-grants/"+strconv.FormatInt(created.ID, 10), nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)

	// Cache invalidated → viewer now sees nothing again (no grants).
	rec = getAuth(handler, "/api/v1/devices", viewer)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &devs))
	require.Equal(t, 0, devs.Total, "after grant deletion viewer sees no devices")
}

func postJSON(t *testing.T, h http.Handler, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getAuth(h http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
