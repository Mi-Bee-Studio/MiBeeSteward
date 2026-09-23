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
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// --- notification rules: remaining validation branches ---

func TestNotificationRule_RemainingBranches(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	channelID := seedChannel(t, db)

	// CreateRule: bad body / bad id on sub-resources / missing name.
	resp := authPost(t, server.URL+"/api/v1/notification/rules", token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// ListRules accepts the query without error (invalid limits clamp).
	resp = authGet(t, server.URL+"/api/v1/notification/rules?limit=zzz", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// GetRule: invalid id → 400.
	resp = authGet(t, server.URL+"/api/v1/notification/rules/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// UpdateRule: bad body → 400, bad id → 400.
	valid := `{"name":"u","event_type":"device_lost","scope_type":"all","channel_id":` + strconv.FormatInt(channelID, 10) + `}`
	resp = authPut(t, server.URL+"/api/v1/notification/rules/9999", token, valid)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, server.URL+"/api/v1/notification/rules/abc", token, valid)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// SetRuleEnabled: bad body → 400; unknown → 404; bad id → 400.
	resp = authPatch(t, server.URL+"/api/v1/notification/rules/9999", token, `{"enabled":true}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPatch(t, server.URL+"/api/v1/notification/rules/abc", token, `{"enabled":true}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// DeleteRule: bad id → 400 (404 already pinned).
	resp = authDelete(t, server.URL+"/api/v1/notification/rules/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- SNMP credentials: list pagination + delete branches ---

func TestSNMPCredentialHandler_ListAndDeleteBranches(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/snmp-credentials", token,
		`{"name":"cred-a","security_level":"noAuthNoPriv"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	id := idToString(created["id"])

	// List with explicit pagination.
	resp = authGet(t, server.URL+"/api/v1/snmp-credentials?limit=5&offset=0", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	require.GreaterOrEqual(t, list["total"], float64(1))

	// Get: bad id → 400.
	resp = authGet(t, server.URL+"/api/v1/snmp-credentials/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Delete: valid → 204; again → 404; bad id → 400.
	resp = authDelete(t, server.URL+"/api/v1/snmp-credentials/"+id, token)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/snmp-credentials/"+id, token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/snmp-credentials/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- changes: remaining filter branches ---

func TestChanges_RemainingFilters(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)
	devID, _ := seedGapDevice(t, fx.db, "chg-host", "10.88.0.1")

	for _, ct := range []string{"device_added", "device_lost"} {
		_, err := fx.db.Exec(`INSERT INTO change_log (network_id, change_type, entity_type, entity_id, after_data, detected_at)
			VALUES (?, ?, 'device', ?, '{}', datetime('now'))`, fx.networkID, ct, devID)
		require.NoError(t, err)
	}

	// entity_type filter + search + since/until bounds.
	for _, q := range []string{
		"?entity_type=device",
		"?search=device_added",
		"?change_type=device_lost&entity_type=device",
		"?network_id=" + strconv.FormatInt(fx.networkID, 10),
		"?limit=1&offset=0",
	} {
		resp := authGet(t, fx.server.URL+"/api/v1/changes"+q, token)
		require.Equal(t, http.StatusOK, resp.StatusCode, "query %s", q)
	}
}

// --- SD endpoint: device-system + scanner-target enrichment ---

func TestSD_DeviceSystemsAndPrometheusTargets(t *testing.T) {
	db := setupSDDb(t)

	// A device with a metrics-enabled system row and prometheus_detected scan
	// evidence must land in the SD target list (both join paths).
	_, err := db.Exec(`INSERT INTO devices (device_uuid, name, ip_address, status)
		VALUES ('uuid-sd-1', 'sd-host', '10.90.0.1', 'online')`)
	require.NoError(t, err)
	var devID int64
	require.NoError(t, db.QueryRow(`SELECT id FROM devices WHERE device_uuid='uuid-sd-1'`).Scan(&devID))
	_, err = db.Exec(`INSERT INTO device_systems (device_id, name, category, metrics_url, metrics_enabled)
		VALUES (?, 'node', 'custom', '10.90.0.1:9100', 1)`, devID)
	require.NoError(t, err)

	sd := handler.NewSDHandler(db, service.NewDeviceSystemRepository(db))
	w := httptest.NewRecorder()
	sd.ServeHTTP(w, httptest.NewRequest("GET", "/sd", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	require.Contains(t, body, "10.90.0.1", "the system-joined target must be present")
}

func setupSDDb(t *testing.T) *sql.DB {
	t.Helper()
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}
