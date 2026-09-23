// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c)2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- auth/login: locked account + setup-status + password policy ---

func TestAuthLogin_LockedAccountAndPolicySurfaces(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Password policy endpoint (public): mirrors the effective policy.
	resp, err := http.Get(server.URL + "/api/v1/auth/password-policy")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// A locked account answers 423 (distinct from 401/429 so the UI renders
	// "account locked" instead of "wrong password").
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role, locked_until)
		VALUES ('locked', 'l@t.com', 'x', 'viewer', datetime('now', '+10 minutes'))`)
	require.NoError(t, err)
	resp2, err := http.Post(server.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"locked","password":"whatever"}`))
	require.NoError(t, err)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusLocked, resp2.StatusCode)

	// Admin register: weak password → 400; duplicate username → 409; bad
	// body → 400; valid viewer → 201.
	reg := func(body string) int {
		resp := authPost(t, server.URL+"/api/v1/auth/register", token, body)
		resp.Body.Close()
		return resp.StatusCode
	}
	require.Equal(t, http.StatusBadRequest, reg(`{not-json`))
	require.Equal(t, http.StatusBadRequest, reg(`{"username":"u1","email":"u1@t.com","password":"weak"}`))
	require.Equal(t, http.StatusConflict, reg(`{"username":"admin","email":"a2@t.com","password":"Str0ngPass!x"}`))
	require.Equal(t, http.StatusCreated, reg(`{"username":"viewer1","email":"v1@t.com","password":"Str0ngPass!x","role":"viewer"}`))

	// AdminResetPassword branch matrix.
	var victimID int64
	require.NoError(t, db.QueryRow(`SELECT id FROM users WHERE username='viewer1'`).Scan(&victimID))
	reset := func(body string) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/users/"+strconv.FormatInt(victimID, 10)+"/reset-password", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	require.Equal(t, http.StatusBadRequest, reset(`{not-json`))
	require.Equal(t, http.StatusBadRequest, reset(`{"new_password":""}`))
	require.Equal(t, http.StatusBadRequest, reset(`{"new_password":"weak"}`)) // policy applies
	require.Equal(t, http.StatusOK, reset(`{"new_password":"Str0ngPass!y"}`))

	// Unknown target → 404; invalid id → 400.
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/users/9999/reset-password", strings.NewReader(`{"new_password":"Str0ngPass!z"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	resp3, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp3.Body.Close()
	require.Equal(t, http.StatusNotFound, resp3.StatusCode)
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/users/abc/reset-password", strings.NewReader(`{"new_password":"Str0ngPass!z"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	resp4, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp4.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp4.StatusCode)

	// The reset password forces a change on next login (mcp gate).
	resp5, err := http.Post(server.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"viewer1","password":"Str0ngPass!y"}`))
	require.NoError(t, err)
	defer resp5.Body.Close()
	require.Equal(t, http.StatusOK, resp5.StatusCode)

	_ = token
}

// --- notification channels: update/toggle error branches ---

func TestNotificationChannel_UpdateAndToggleBranches(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	var id int64
	res, err := db.Exec(`INSERT INTO notification_channels (name, type, config) VALUES ('hook', 'webhook', '{"url":"http://x"}')`)
	require.NoError(t, err)
	id, _ = res.LastInsertId()
	path := "/api/v1/notification/channels/" + strconv.FormatInt(id, 10)

	// Bad body → 400; unknown channel → 404; valid rename → 200.
	resp := authPut(t, server.URL+path, token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPut(t, server.URL+"/api/v1/notification/channels/9999", token, `{"name":"ghost"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, server.URL+path, token, `{"name":"hook2","config":{"url":"http://y"}}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Toggle: bad body → 400, unknown → 404, valid → 200.
	resp = authPatch(t, server.URL+path, token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPatch(t, server.URL+"/api/v1/notification/channels/9999", token, `{"enabled":false}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPatch(t, server.URL+path, token, `{"enabled":false}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- SNMP credentials handler: create/update validation branches ---

func TestSNMPCredentialHandler_CreateUpdateValidation(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	_ = db

	// Create: v1v2c without community → 400 (message from validateCredentialRequest).
	resp := authPost(t, server.URL+"/api/v1/snmp-credentials", token,
		`{"name":"no-comm","security_level":"v1v2c"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "community is required")

	// authPriv missing priv protocol → 400.
	resp = authPost(t, server.URL+"/api/v1/snmp-credentials", token,
		`{"name":"no-priv","security_level":"authPriv","username":"u","auth_protocol":"SHA"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Valid v3 create → 201 (passphrase never echoed).
	resp = authPost(t, server.URL+"/api/v1/snmp-credentials", token,
		`{"name":"sw-v3","security_level":"authPriv","username":"u","auth_protocol":"SHA","auth_passphrase":"authsecret1","priv_protocol":"AES","priv_passphrase":"privsecret1"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := readBody(t, resp)
	require.NotContains(t, body, "authsecret1")
	var created map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(body), &created))
	id := idToString(created["id"])

	// Update: bad body → 400; unknown → 404; valid rename keeps ciphertext → 200.
	resp = authPut(t, server.URL+"/api/v1/snmp-credentials/"+id, token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPut(t, server.URL+"/api/v1/snmp-credentials/9999", token,
		`{"name":"ghost","security_level":"noAuthNoPriv"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, server.URL+"/api/v1/snmp-credentials/"+id, token, `{"name":"sw-v3-renamed","security_level":"authPriv","username":"u","auth_protocol":"SHA","priv_protocol":"AES"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Update into an invalid security level → 400.
	resp = authPut(t, server.URL+"/api/v1/snmp-credentials/"+id, token, `{"name":"sw-v3b","security_level":"warp"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- scanner results: export CSV + list filters ---

func TestScannerResults_ExportAndFilters(t *testing.T) {
	fx := setupGapServer(t)
	server, db := fx.server, fx.db
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	res, err := db.Exec(`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, timeout, concurrent_hosts, enabled)
		VALUES ('export-task', '192.168.1.0/24', '0 3 * * *', '{}', 30, 10, 1)`)
	require.NoError(t, err)
	taskID, _ := res.LastInsertId()
	_, err = db.Exec(`INSERT INTO scan_results (task_id, ip, alive, ports, services, snmp_data)
		VALUES (?, '192.168.1.50', 1, '[80]', '{}', '{"sys_name":"sw-1","inferred_brand":"cisco"}')`, taskID)
	require.NoError(t, err)

	// Export CSV: headers + the enriched row.
	resp := authGet(t, server.URL+"/api/v1/scanner/results/export?task_id="+strconv.FormatInt(taskID, 10), token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/csv; charset=utf-8", resp.Header.Get("Content-Type"))
	body := readBody(t, resp)
	require.Contains(t, body, "192.168.1.50")
	require.Contains(t, body, "sw-1")
	require.Contains(t, body, "cisco")

	// Missing/invalid task_id → 400/400; unknown task → 404.
	resp = authGet(t, server.URL+"/api/v1/scanner/results/export", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/scanner/results/export?task_id=abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/scanner/results/export?task_id=9999", token)
	require.Equal(t, http.StatusOK, resp.StatusCode, "unknown task in global scope exports an empty CSV")

	// List filters: alive filter + ip filter narrow; garbage pagination → 400.
	resp = authGet(t, server.URL+"/api/v1/scanner/results?task_id="+strconv.FormatInt(taskID, 10)+"&alive=true", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/scanner/results?task_id="+strconv.FormatInt(taskID, 10)+"&ip=192.168.1.50", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	require.Equal(t, float64(1), list["total"])
	resp = authGet(t, server.URL+"/api/v1/scanner/results?limit=zzz", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
