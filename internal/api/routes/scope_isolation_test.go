// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/domain"
)

// tokenForUser signs a JWT carrying a specific user_id + role (tokenForRole in
// scanner_rbac_test.go pins user_id=1; the scope tests need user_id=2 for the
// seeded admin).
func tokenForUser(t *testing.T, secret string, userID int64, role string) string {
	t.Helper()
	auth := jwtauth.New("HS256", []byte(secret), nil)
	_, token, err := auth.Encode(map[string]any{"user_id": float64(userID), "role": role})
	require.NoError(t, err)
	return token
}

// These tests pin object-level network scope (#138 Phase 2): in closed mode a
// non-admin user sees only the devices on networks they hold a grant for
// (device list filtered; device detail/sub-resources 403 out of scope), while
// admin and open mode are unrestricted. They exercise the REAL NewRouter with a
// closed-mode config and a seeded grant.

// scopeTestDB seeds two networks, a device on each, a viewer user, and (when
// granted) a grant for network 1 only.
func scopeTestDB(t *testing.T, grantNetwork1 bool) *sql.DB {
	t.Helper()
	db := newTestDB(t)
	_, err := db.Exec(`
		INSERT INTO networks (id, name, cidr) VALUES (1, 'lan-1', '10.0.1.0/24'), (2, 'lan-2', '10.0.2.0/24');
		INSERT INTO devices (id, name, ip_address, type, status, network_id) VALUES
			(10, 'dev-in-net1', '10.0.1.5', 'pc', 'online', 1),
			(20, 'dev-in-net2', '10.0.2.5', 'pc', 'online', 2);
		INSERT INTO users (id, username, email, password_hash, role) VALUES
			(1, 'viewer1', 'v1@example.com', 'x', 'viewer'),
			(2, 'admin1', 'a1@example.com', 'x', 'admin');
	`)
	require.NoError(t, err)
	if grantNetwork1 {
		_, err = db.Exec(`INSERT INTO user_network_grants (user_id, network_id) VALUES (1, 1)`)
		require.NoError(t, err)
	}
	return db
}

func closedTestConfig() *config.Config {
	cfg := newTestConfig()
	cfg.RBAC.ScopeDefault = string(domain.ScopeModeClosed)
	return cfg
}

type deviceListJSON struct {
	Devices []struct {
		ID        int64  `json:"id"`
		NetworkID *int64 `json:"network_id"`
	} `json:"devices"`
	Total int `json:"total"`
}

// TestScope_ClosedMode_ViewerSeesOnlyGrantedNetwork: a viewer granted network 1
// lists only network-1 devices and is 403'd on a network-2 device.
func TestScope_ClosedMode_ViewerSeesOnlyGrantedNetwork(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, true)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	tok := tokenForRole(t, cfg.Auth.JWTSecret, "viewer") // user_id=1, role=viewer

	// List: only the network-1 device (id 10) should appear.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 1, body.Total, "scoped viewer should see exactly 1 device (network 1)")
	require.Len(t, body.Devices, 1)
	require.Equal(t, int64(10), body.Devices[0].ID)

	// In-scope device detail: passes the gate (handler then 200s).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/10", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.NotEqual(t, http.StatusForbidden, rec.Code)
	require.NotEqual(t, http.StatusUnauthorized, rec.Code)

	// Out-of-scope device detail: 403.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/20", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, "scoped viewer must be 403 on network-2 device")

	// Out-of-scope sub-resource: also 403 (ValidateDeviceScope covers sub-resources).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/20/neighbors", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, "scoped viewer must be 403 on network-2 sub-resource")
}

// TestScope_ClosedMode_ViewerWithNoGrantsSeesNothing: closed mode + no grants →
// the device list is empty (fail-closed, not fail-open).
func TestScope_ClosedMode_ViewerWithNoGrantsSeesNothing(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, false) // no grants
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	tok := tokenForRole(t, cfg.Auth.JWTSecret, "viewer")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 0, body.Total, "closed-mode viewer with no grants sees no devices")
}

// TestScope_AdminBypassesScope: even in closed mode, admin sees every device.
func TestScope_AdminBypassesScope(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, true)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	// admin1 is user_id=2 in the seed.
	tok := tokenForUser(t, cfg.Auth.JWTSecret, 2, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 2, body.Total, "admin bypasses scope — sees both networks' devices")
}

// TestScope_OpenMode_ViewerSeesEverything: open mode (default) ignores grants —
// a viewer sees all devices regardless of grants. Backward-compatible default.
func TestScope_OpenMode_ViewerSeesEverything(t *testing.T) {
	cfg := newTestConfig() // open mode (default)
	cfg.RBAC.ScopeDefault = string(domain.ScopeModeOpen)
	db := scopeTestDB(t, false)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	tok := tokenForRole(t, cfg.Auth.JWTSecret, "viewer")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 2, body.Total, "open mode: viewer sees all devices")
}
