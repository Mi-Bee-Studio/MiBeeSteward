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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/config"
)

// The settings-center API: admin reads/writes the auth policy overlay, and
// the change is visible through the PUBLIC /auth/password-policy endpoint
// without a restart, the end-to-end "edit password strength from the web UI"
// contract the SPA settings page relies on.
func TestSettings_AuthPolicyOverlayLifecycle(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Initial state: config-sourced, relaxed default (no special chars).
	resp, err := doAuthed(t, server, http.MethodGet, "/api/v1/settings/auth", token, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var initial map[string]any
	decodeJSON(t, resp, &initial)
	require.Equal(t, "config", initial["password_policy_source"])

	// PUT an overlay: min_length 12.
	putBody := `{"password_policy":{"min_length":12,"require_uppercase":true,"require_lowercase":true,"require_digit":true,"require_special":false}}`
	resp2, err := doAuthed(t, server, http.MethodPut, "/api/v1/settings/auth", token, bytes.NewBufferString(putBody))
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var updated map[string]any
	decodeJSON(t, resp2, &updated)
	require.Equal(t, "overlay", updated["password_policy_source"])
	policy, _ := updated["password_policy"].(map[string]any)
	require.NotNil(t, policy)
	require.Equal(t, float64(12), policy["min_length"])

	// The public policy endpoint reflects the overlay immediately.
	resp3, err := http.Get(server.URL + "/api/v1/auth/password-policy")
	require.NoError(t, err)
	defer resp3.Body.Close()
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	var public map[string]any
	decodeJSON(t, resp3, &public)
	require.Equal(t, float64(12), public["min_length"])

	// And the register path enforces it (admin token holds CapUserManage).
	regBody := `{"username":"bob","email":"bob@example.com","password":"Short1a","role":"user"}` // 7 chars
	resp4, err := doAuthed(t, server, http.MethodPost, "/api/v1/auth/register", token, bytes.NewBufferString(regBody))
	require.NoError(t, err)
	defer resp4.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp4.StatusCode, "min_length=12 overlay must reject a 7-char password")
}

func TestSettings_Validation(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	for _, body := range []string{
		`{"password_policy":{"min_length":0}}`,
		`{"password_policy":{"min_length":5000}}`,
		`{"lockout":{"max_failed_attempts":0,"lock_minutes":30}}`,
		`{"lockout":{"max_failed_attempts":5,"lock_minutes":0}}`,
		`{}`,
	} {
		resp, err := doAuthed(t, server, http.MethodPut, "/api/v1/settings/auth", token, bytes.NewBufferString(body))
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body %s must be rejected", body)
	}
}

// The probe policy surface: PUT /settings/probes persists the switch in the
// overlay and echoes the effective post-update view. (The subscriber reseed
// wiring — the "takes effect immediately" half — is covered at the routes
// layer where the real router runs: TestRoutes_ProbeSettingsSwitchReseeds.)
func TestSettings_ProbePolicyLifecycle(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Initial state: config-sourced, default-on (absent key = shipped ON).
	resp, err := doAuthed(t, server, http.MethodGet, "/api/v1/settings/probes", token, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var initial map[string]any
	decodeJSON(t, resp, &initial)
	require.Equal(t, "config", initial["quality_source"])
	require.Equal(t, true, initial["quality"].(map[string]any)["enabled"], "absent key resolves ON")
	require.Equal(t, "config", initial["autogen_source"])
	require.Equal(t, false, initial["autogen"].(map[string]any)["enabled"], "autogen stays off by default")

	// Flip the quality switch OFF: the overlay row lands and is echoed.
	putBody := `{"quality":{"enabled":false},"autogen":{"enabled":true,"max_targets":50,"interval_seconds":120}}`
	resp2, err := doAuthed(t, server, http.MethodPut, "/api/v1/settings/probes", token, bytes.NewBufferString(putBody))
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var updated map[string]any
	decodeJSON(t, resp2, &updated)
	require.Equal(t, "overlay", updated["quality_source"])
	require.Equal(t, false, updated["quality"].(map[string]any)["enabled"])
	require.Equal(t, "overlay", updated["autogen_source"])
	autogen, _ := updated["autogen"].(map[string]any)
	require.Equal(t, true, autogen["enabled"])
	require.Equal(t, float64(50), autogen["max_targets"])
	require.Equal(t, float64(120), autogen["interval_seconds"])
}

func TestSettings_ProbeValidation(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	for _, body := range []string{
		`{}`,
		`{"quality":{}}`,
		`{"autogen":{"max_targets":5000,"enabled":true}}`,
		`{"autogen":{"interval_seconds":1,"enabled":true}}`,
		`not-json`,
	} {
		resp, err := doAuthed(t, server, http.MethodPut, "/api/v1/settings/probes", token, bytes.NewBufferString(body))
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, "body %s must be rejected", body)
	}
}

// The overlay-unavailable degradation (settingsSvc nil at startup): writes
// 503, reads still serve the config layer — the production contract when the
// system_settings table cannot load.
func TestSettings_ProbesOverlayUnavailable(t *testing.T) {
	h := handler.NewSettingsHandler(nil, nil, &config.Config{}, nil)

	w := httptest.NewRecorder()
	h.UpdateProbes(w, httptest.NewRequest(http.MethodPut, "/api/v1/settings/probes",
		bytes.NewBufferString(`{"quality":{"enabled":true}}`)))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	w2 := httptest.NewRecorder()
	h.GetProbes(w2, httptest.NewRequest(http.MethodGet, "/api/v1/settings/probes", nil))
	require.Equal(t, http.StatusOK, w2.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
	require.Equal(t, "config", resp["quality_source"])
	require.Equal(t, true, resp["quality"].(map[string]any)["enabled"])
}

// Non-admin roles are gated off the settings surface (CapUserManage).
func TestSettings_RequiresAdmin(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	adminToken := loginAsAdmin(t, server)

	// Create a viewer (register is admin-gated) and log in as them.
	regBody := `{"username":"viewer1","email":"viewer1@example.com","password":"Viewer1Pass","role":"viewer"}`
	resp, err := doAuthed(t, server, http.MethodPost, "/api/v1/auth/register", adminToken, bytes.NewBufferString(regBody))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	loginResp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json",
		bytes.NewBufferString(`{"username":"viewer1","password":"Viewer1Pass"}`))
	require.NoError(t, err)
	defer loginResp.Body.Close()
	var loginResult map[string]any
	decodeJSON(t, loginResp, &loginResult)
	viewerToken, _ := loginResult["token"].(string)
	require.NotEmpty(t, viewerToken)

	got, err := doAuthed(t, server, http.MethodGet, "/api/v1/settings/auth", viewerToken, nil)
	require.NoError(t, err)
	got.Body.Close()
	require.Equal(t, http.StatusForbidden, got.StatusCode)

	// /system stays readable for every signed-in role.
	sysResp, err := doAuthed(t, server, http.MethodGet, "/api/v1/system", viewerToken, nil)
	require.NoError(t, err)
	defer sysResp.Body.Close()
	require.Equal(t, http.StatusOK, sysResp.StatusCode)
	var sys map[string]any
	decodeJSON(t, sysResp, &sys)
	require.Contains(t, sys, "version")
}

func TestSystem_RequiresAuth(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/system")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestSystem_NetworkInterfaces pins the #678 first-use suggestion endpoint:
// any signed-in user gets the host's interface snapshot (interfaces list +
// container flag; the warning key is machine-dependent and only asserted
// when present).
func TestSystem_NetworkInterfaces(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp, err := doAuthed(t, server, http.MethodGet, "/api/v1/system/network-interfaces", token, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Interfaces []struct {
			Name          string `json:"name"`
			IPv4          string `json:"ipv4"`
			PrefixLen     int    `json:"prefix_len"`
			CIDR          string `json:"cidr"`
			Kind          string `json:"kind"`
			Primary       bool   `json:"primary"`
			Addresses     int    `json:"addresses"`
			SuggestedCIDR string `json:"suggested_cidr"`
		} `json:"interfaces"`
		Container bool   `json:"container"`
		Warning   string `json:"warning"`
	}
	decodeJSON(t, resp, &body)
	require.NotNil(t, body.Interfaces)
	for _, iface := range body.Interfaces {
		require.NotEmpty(t, iface.Name)
		require.NotContains(t, iface.IPv4, "127.0.0.1", "loopback interfaces are never listed")
		require.Contains(t, []string{"lan", "wireless", "virtual", "vpn"}, iface.Kind)
		require.Positive(t, iface.Addresses)
		require.NotEmpty(t, iface.SuggestedCIDR)
	}
	if body.Warning != "" {
		require.Contains(t, []string{"bridge_container", "no_lan"}, body.Warning)
	}

	// Anonymous access is rejected like /system.
	resp2, err := http.Get(server.URL + "/api/v1/system/network-interfaces")
	require.NoError(t, err)
	resp2.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

// doAuthed issues a JSON request with a bearer token.
func doAuthed(t *testing.T, server *httptest.Server, method, path, token string, body io.Reader) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(method, server.URL+path, body)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}
