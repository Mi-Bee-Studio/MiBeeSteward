// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"testing"

	"time"

	"github.com/stretchr/testify/require"
)

// --- Dashboard endpoints ---

func TestDashboardEndpoints_ConfigsAndQueries(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Widget validation matrix (shared by create + update).
	cases := []struct {
		name string
		body string
		want int
		msg  string
	}{
		{"no name", `{"type":"gauge","query":"up"}`, 400, "name is required"},
		{"chart type required", `{"name":"w","type":"list","query":"up"}`, 400, "type must be one of"},
		{"query required for prometheus", `{"name":"w","type":"gauge"}`, 400, "query is required"},
		{"unknown builtin template", `{"name":"w","type":"list","data_source":"builtin","query":"builtin:nope"}`, 400, "unknown builtin widget template"},
		{"builtin type mismatch", `{"name":"w","type":"pie","data_source":"builtin","query":"builtin:offline_devices"}`, 400, "must use type list"},
		{"bad data source", `{"name":"w","type":"gauge","data_source":"graphite","query":"x"}`, 400, "data_source must be one of"},
		{"victoriametrics alias ok", `{"name":"vm","type":"line","data_source":"victoriametrics","query":"up"}`, 201, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := authPost(t, server.URL+"/api/v1/dashboard/configs", token, tc.body)
			require.Equal(t, tc.want, resp.StatusCode)
			if tc.msg != "" {
				require.Contains(t, readBody(t, resp), tc.msg)
			}
		})
	}

	// Create a builtin widget, then list (wrapped shape) / update / delete.
	resp := authPost(t, server.URL+"/api/v1/dashboard/configs", token,
		`{"name":"offline","type":"list","data_source":"builtin","query":"builtin:offline_devices"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, "builtin", created["data_source"])
	configID := idToString(created["id"])

	resp = authGet(t, server.URL+"/api/v1/dashboard/configs", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	// {configs: [...]} wrapper, a bare array once made every widget invisible (#247)
	configs, ok := list["configs"].([]interface{})
	require.True(t, ok)
	require.Len(t, configs, 2)
	require.Equal(t, float64(2), list["total"])

	resp = authPut(t, server.URL+"/api/v1/dashboard/configs/"+configID, token,
		`{"name":"renamed","type":"list","data_source":"builtin","query":"builtin:probe_status"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "renamed", updated["name"])

	resp = authPut(t, server.URL+"/api/v1/dashboard/configs/abc", token, `{}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPut(t, server.URL+"/api/v1/dashboard/configs/0", token, `{}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp = authDelete(t, server.URL+"/api/v1/dashboard/configs/"+configID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/dashboard/configs/x", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDashboardEndpoints_OverviewAndQueryProxy(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	seedCoverageDevice(t, db, "ov-1", "10.7.0.1")

	resp := authGet(t, server.URL+"/api/v1/dashboard/overview", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var overview map[string]interface{}
	decodeJSON(t, resp, &overview)
	devices, ok := overview["devices"].(map[string]interface{})
	require.True(t, ok, "overview must carry the devices aggregate")
	require.Equal(t, float64(1), devices["total"])

	// Query proxy param validation (no data source configured yet).
	resp = authGet(t, server.URL+"/api/v1/dashboard/query", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/dashboard/query?query=up", token)
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "failed to query data source")

	resp = authGet(t, server.URL+"/api/v1/dashboard/query_range?query=up", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "start, end, and step")
	resp = authGet(t, server.URL+"/api/v1/dashboard/query_range?query=up&start=0&end=1&step=15", token)
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// --- Heartbeat config endpoints ---

func TestHeartbeatConfigEndpoints_CRUD(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	deviceID := seedCoverageDevice(t, db, "hb-host", "10.7.1.1")
	devPath := "/api/v1/devices/" + strconv.FormatInt(deviceID, 10) + "/heartbeat-configs"

	// Validation: bad id / bad json / missing method / missing target / bad method.
	resp := authPost(t, server.URL+"/api/v1/devices/0/heartbeat-configs", token, `{"method":"icmp"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+devPath, token, `{nope`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+devPath, token, `{"target":"10.7.1.1"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "method is required")
	resp = authPost(t, server.URL+devPath, token, `{"method":"icmp"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "target is required")
	resp = authPost(t, server.URL+devPath, token, `{"method":"carrier","target":"10.7.1.1"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "method must be one of")

	// Create with defaults (interval/timeout/community/oid all omitted).
	resp = authPost(t, server.URL+devPath, token, `{"method":"snmp","target":"10.7.1.1"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, float64(30), created["interval_seconds"])
	require.Equal(t, float64(5), created["timeout_seconds"])
	require.Equal(t, "public", created["snmp_community"])
	configID := idToString(created["id"])

	// List is wrapped + never nil.
	resp = authGet(t, server.URL+devPath, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	configs, ok := list["configs"].([]interface{})
	require.True(t, ok)
	require.Len(t, configs, 1)

	// Merge-update: omit fields → keep existing.
	resp = authPut(t, server.URL+"/api/v1/heartbeat-configs/"+configID, token, `{"target":"10.7.1.2"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "10.7.1.2", updated["target"])
	require.Equal(t, "snmp", updated["method"])

	// Update missing config → 404; invalid id → 400.
	resp = authPut(t, server.URL+"/api/v1/heartbeat-configs/9999", token, `{"target":"x"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, server.URL+"/api/v1/heartbeat-configs/zz", token, `{}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Delete + delete-again 404 + invalid id 400.
	resp = authDelete(t, server.URL+"/api/v1/heartbeat-configs/"+configID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/heartbeat-configs/"+configID, token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/heartbeat-configs/zz", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHeartbeatResults_ParamValidation(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	deviceID := seedCoverageDevice(t, db, "hb-res", "10.7.2.1")

	// Results: invalid device id → 400; valid id + empty store → wrapped empty list.
	resp := authGet(t, server.URL+"/api/v1/devices/0/heartbeat-results", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-results", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var results map[string]interface{}
	decodeJSON(t, resp, &results)
	require.Contains(t, results, "results")

	// History: from/to required, ISO-8601, ordered, ≤90 days.
	base := "/api/v1/devices/" + strconv.FormatInt(deviceID, 10) + "/heartbeat-history"
	resp = authGet(t, server.URL+base, token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "'from'")
	resp = authGet(t, server.URL+base+"?from=not-a-date&to=2026-01-02T00:00:00Z", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+base+"?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "must be after")
	resp = authGet(t, server.URL+base+"?from=2025-01-01T00:00:00Z&to=2026-06-01T00:00:00Z", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "max 90 days")
	resp = authGet(t, server.URL+base+"?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Stats: same from/to contract.
	statsBase := "/api/v1/devices/" + strconv.FormatInt(deviceID, 10) + "/heartbeat-stats"
	resp = authGet(t, server.URL+statsBase, token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+statsBase+"?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- SNMP credential endpoints ---

func TestSNMPCredentialEndpoints_MaskingAndCRUD(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// authPriv v3 credential: passphrases arrive plaintext, never leave.
	resp := authPost(t, server.URL+"/api/v1/snmp-credentials", token,
		`{"name":"core-sw","security_level":"authPriv","username":"snmpv3","auth_protocol":"SHA","auth_passphrase":"authsecret","priv_protocol":"AES","priv_passphrase":"privsecret"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := readBody(t, resp)
	require.Contains(t, body, `"has_auth":true`)
	require.Contains(t, body, `"has_priv":true`)
	require.NotContains(t, body, "authsecret")
	require.NotContains(t, body, "privsecret")
	// The DB row stores ciphertext, not the plaintext.
	var authEnc, privEnc string
	require.NoError(t, db.QueryRow(`SELECT auth_passphrase_enc, priv_passphrase_enc FROM snmp_credentials WHERE name='core-sw'`).Scan(&authEnc, &privEnc))
	require.NotContains(t, authEnc, "authsecret")
	require.NotContains(t, privEnc, "privsecret")
	require.NotEmpty(t, authEnc)

	var created map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(body), &created))
	credID := idToString(created["id"])

	// Duplicate name → 409 with the specific message.
	resp = authPost(t, server.URL+"/api/v1/snmp-credentials", token,
		`{"name":"core-sw","security_level":"noAuthNoPriv"}`)
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "already exists")

	// Validation: missing name / bad security level.
	resp = authPost(t, server.URL+"/api/v1/snmp-credentials", token, `{"security_level":"noAuthNoPriv"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/snmp-credentials", token, `{"name":"x","security_level":"bogus"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// List is paginated + masked; get by id; get missing → 404; bad id → 400.
	resp = authGet(t, server.URL+"/api/v1/snmp-credentials", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	creds, ok := list["credentials"].([]interface{})
	require.True(t, ok)
	require.Len(t, creds, 1)

	resp = authGet(t, server.URL+"/api/v1/snmp-credentials/"+credID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/snmp-credentials/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/snmp-credentials/zz", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Update: empty passphrase = leave unchanged; new passphrase = re-encrypted.
	resp = authPut(t, server.URL+"/api/v1/snmp-credentials/"+credID, token,
		`{"name":"core-sw2","security_level":"authPriv","username":"snmpv3","auth_protocol":"SHA","priv_protocol":"AES"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var authEnc2 string
	require.NoError(t, db.QueryRow(`SELECT auth_passphrase_enc FROM snmp_credentials WHERE name='core-sw2'`).Scan(&authEnc2))
	require.Equal(t, authEnc, authEnc2, "empty passphrase must keep the existing ciphertext")
	resp = authPut(t, server.URL+"/api/v1/snmp-credentials/"+credID, token,
		`{"name":"core-sw2","security_level":"authPriv","username":"snmpv3","auth_protocol":"SHA","auth_passphrase":"rotated","priv_protocol":"AES"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var authEnc3 string
	require.NoError(t, db.QueryRow(`SELECT auth_passphrase_enc FROM snmp_credentials WHERE name='core-sw2'`).Scan(&authEnc3))
	require.NotEqual(t, authEnc, authEnc3)

	// Delete + delete missing.
	resp = authDelete(t, server.URL+"/api/v1/snmp-credentials/"+credID, token)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp = authDelete(t, server.URL+"/api/v1/snmp-credentials/"+credID, token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Scanner endpoints ---

func TestScannerScanEndpoint_ValidationBoundaries(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	base := server.URL + "/api/v1/scanner/scan"

	// Bad JSON / missing targets.
	resp := authPost(t, base, token, `{nope`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, base, token, `{"community":"public"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "targets is required")

	// Unparseable target.
	resp = authPost(t, base, token, `{"targets":"not-an-ip"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Invalid port spec with valid targets.
	resp = authPost(t, base, token, `{"targets":"192.0.2.1","ports":"abc"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "ports:")

	// Range too large for a synchronous scan → 413 pointing at the async API.
	resp = authPost(t, base, token, `{"targets":"10.0.0.0/20"}`)
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "scanner/tasks")
}

func TestScannerAddDevicesEndpoint(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	base := server.URL + "/api/v1/scanner/add-devices"

	resp := authPost(t, base, token, `{nope`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, base, token, `{"devices":[]}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "must not be empty")

	// Batch persist: both rows land via the device bridge (a bad type is
	// logged-and-skipped by the bridge, not returned as an HTTP error, the
	// logged-and-skipped contract).
	resp = authPost(t, base, token, `{"devices":[
		{"ip":"10.7.3.1","name":"manual-1","type":"pc","brand":"Generic"},
		{"ip":"10.7.3.4","name":"manual-2","type":"server"}
	]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var added map[string]interface{}
	decodeJSON(t, resp, &added)
	require.Equal(t, float64(2), added["added"])
	require.Empty(t, added["errors"])

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address LIKE '10.7.3.%'`).Scan(&count))
	require.Equal(t, 2, count)
}

// TestScannerScanEndpoint_LoopbackHappyPath runs one REAL (tiny) scan against
// 127.0.0.1, the coverage server's engine allows reserved targets. A local
// TCP listener guarantees at least one open port; ICMP echo on loopback is
// always reachable. Pins the full pipeline: engine scan → reportToHost →
// device-bridge persistence (the manual-sync-scan contract).
func TestScannerScanEndpoint_LoopbackHappyPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/scanner/scan", token,
		`{"targets":"127.0.0.1","timeout":1,"ports":"`+strconv.Itoa(port)+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var scan map[string]interface{}
	decodeJSON(t, resp, &scan)
	require.Equal(t, float64(1), scan["total"])
	require.GreaterOrEqual(t, scan["alive"], float64(1))
	hosts := scan["hosts"].([]interface{})
	require.Len(t, hosts, 1)
	require.Equal(t, "127.0.0.1", hosts[0].(map[string]interface{})["ip"])

	// The alive host went through the device bridge → devices row exists.
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address='127.0.0.1'`).Scan(&count))
	require.Equal(t, 1, count)
}

// TestHeartbeatHandler_StatsAndHistoryParams pins the stats/history surfaces
// over the coverage server (with data present + parameter clamps).
func TestHeartbeatHandler_StatsAndHistoryParams(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	deviceID := seedCoverageDevice(t, db, "hb-stats-host", "10.99.0.1")

	// Seed one config + one result row via the service-backed endpoints.
	resp := authPost(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-configs", token,
		`{"method":"icmp","target":"10.99.0.1","interval_seconds":60}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Stats: bad device id / missing from-to / bad from → 400; the full
	// from/to matrix on a real device → 200.
	now := time.Now().UTC()
	fromStr := now.Add(-time.Hour).Format(time.RFC3339)
	toStr := now.Format(time.RFC3339)
	resp = authGet(t, server.URL+"/api/v1/devices/abc/heartbeat-stats", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-stats", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "missing from/to is a 400")
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-stats?from=not-a-date&to="+toStr, token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-stats?from="+fromStr+"&to="+toStr, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// History: bad device id → 400; missing from/to → 400; a valid window → 200.
	resp = authGet(t, server.URL+"/api/v1/devices/abc/heartbeat-history", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-history", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-history?from="+fromStr+"&to="+toStr, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Results: bad id → 400 + limit clamp paths.
	resp = authGet(t, server.URL+"/api/v1/devices/abc/heartbeat-results", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-results?limit=99999", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
