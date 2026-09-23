// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// setupHBHandler builds a HeartbeatHandler over a fresh main DB + heartbeat
// store and seeds one device row (heartbeat configs FK to it).
func setupHBHandler(t *testing.T) (*HeartbeatHandler, int64) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	res, err := conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid)
		VALUES ('hb-dev', 'camera', '192.0.2.50', '02:00:00:00:05:00', 'online', 'hb-uuid-1')`)
	require.NoError(t, err)
	devID, err := res.LastInsertId()
	require.NoError(t, err)

	store, err := service.OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return NewHeartbeatHandler(service.NewHeartbeatService(conn, store, &config.Config{})), devID
}

// TestHeartbeatConfig_CreateDefaultsAndValidation covers the create-path
// defaulting ladder (interval/timeout/community/oid/enabled) and the
// device-id guard.
func TestHeartbeatConfig_CreateDefaultsAndValidation(t *testing.T) {
	h, devID := setupHBHandler(t)

	// Defaults applied when the request omits them: interval→30, timeout→5,
	// community→public, oid→SysUpTimeOID, enabled→1.
	rw := httptest.NewRecorder()
	h.CreateConfig(rw, reqWithBodyParams(http.MethodPost, "/x",
		`{"method":"icmp","target":"192.0.2.50"}`, map[string]string{"id": strconv.FormatInt(devID, 10)}))
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
	require.Contains(t, rw.Body.String(), `"interval_seconds":30`)
	require.Contains(t, rw.Body.String(), `"timeout_seconds":5`)
	require.Contains(t, rw.Body.String(), `"snmp_community":"public"`)

	// Explicit values pass through, enabled=0 honored.
	rw = httptest.NewRecorder()
	h.CreateConfig(rw, reqWithBodyParams(http.MethodPost, "/x",
		`{"method":"tcp","target":"192.0.2.50:80","interval_seconds":60,"timeout_seconds":2,"snmp_community":"private","snmp_oid":"1.3.6.1.2.1.1.3.0","enabled":0}`,
		map[string]string{"id": strconv.FormatInt(devID, 10)}))
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
	require.Contains(t, rw.Body.String(), `"interval_seconds":60`)
	require.Contains(t, rw.Body.String(), `"enabled":0`)

	// Bad device id → 400; bad JSON → 400.
	rw = httptest.NewRecorder()
	h.CreateConfig(rw, reqWithBodyParams(http.MethodPost, "/x", `{}`, map[string]string{"id": "abc"}))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.CreateConfig(rw, reqWithBodyParams(http.MethodPost, "/x", "{nope", map[string]string{"id": strconv.FormatInt(devID, 10)}))
	require.Equal(t, http.StatusBadRequest, rw.Code)
}

// TestHeartbeatConfig_UpdateMergeAndValidation covers the update merge
// branches (nil = keep, invalid method → 400, non-positive interval/timeout
// ignored) and the unknown-config 404.
func TestHeartbeatConfig_UpdateMergeAndValidation(t *testing.T) {
	h, devID := setupHBHandler(t)

	rw := httptest.NewRecorder()
	h.CreateConfig(rw, reqWithBodyParams(http.MethodPost, "/x",
		`{"method":"icmp","target":"192.0.2.50","interval_seconds":30,"timeout_seconds":5,"snmp_community":"public","snmp_oid":"1.3.6.1.2.1.1.3.0","enabled":1}`,
		map[string]string{"id": strconv.FormatInt(devID, 10)}))
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
	cfgID := int64(1)

	// Merge: method+target+community updated; interval left nil (kept); a
	// NON-POSITIVE interval is ignored (keeps 30).
	rw = httptest.NewRecorder()
	h.UpdateConfig(rw, reqWithBodyParams(http.MethodPut, "/x",
		`{"method":"tcp","target":"192.0.2.50:443","interval_seconds":0,"timeout_seconds":-1,"snmp_community":"private","enabled":0}`,
		map[string]string{"id": strconv.FormatInt(devID, 10), "configId": strconv.FormatInt(cfgID, 10)}))
	require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
	require.Contains(t, rw.Body.String(), `"method":"tcp"`)
	require.Contains(t, rw.Body.String(), `"target":"192.0.2.50:443"`)
	require.Contains(t, rw.Body.String(), `"interval_seconds":30`)
	require.Contains(t, rw.Body.String(), `"snmp_community":"private"`)
	require.Contains(t, rw.Body.String(), `"enabled":0`)

	// Invalid method → 400.
	rw = httptest.NewRecorder()
	h.UpdateConfig(rw, reqWithBodyParams(http.MethodPut, "/x",
		`{"method":"grpc"}`, map[string]string{"id": strconv.FormatInt(devID, 10), "configId": strconv.FormatInt(cfgID, 10)}))
	require.Equal(t, http.StatusBadRequest, rw.Code)

	// Unknown config id: the UPDATE matches no row and the handler does not
	// check RowsAffected, so this is a 200 no-op (pinned as-is; changing it is
	// a behavior decision, not a coverage fix).
	rw = httptest.NewRecorder()
	h.UpdateConfig(rw, reqWithBodyParams(http.MethodPut, "/x", `{}`,
		map[string]string{"id": strconv.FormatInt(devID, 10), "configId": "999"}))
	require.Equal(t, http.StatusOK, rw.Code)
	rw = httptest.NewRecorder()
	h.UpdateConfig(rw, reqWithBodyParams(http.MethodPut, "/x", `{}`,
		map[string]string{"id": "abc", "configId": "1"}))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.UpdateConfig(rw, reqWithBodyParams(http.MethodPut, "/x", "{nope",
		map[string]string{"id": strconv.FormatInt(devID, 10), "configId": "1"}))
	require.Equal(t, http.StatusBadRequest, rw.Code)

	// Delete happy path + unknown → 404.
	rw = httptest.NewRecorder()
	h.DeleteConfig(rw, reqWithBodyParams(http.MethodDelete, "/x", "",
		map[string]string{"id": strconv.FormatInt(devID, 10), "configId": strconv.FormatInt(cfgID, 10)}))
	require.Equal(t, http.StatusOK, rw.Code)
	rw = httptest.NewRecorder()
	h.DeleteConfig(rw, reqWithBodyParams(http.MethodDelete, "/x", "",
		map[string]string{"id": strconv.FormatInt(devID, 10), "configId": "999"}))
	require.Equal(t, http.StatusNotFound, rw.Code)
}

// TestHeartbeatResults_WindowParsing covers ListResults' date-window parsing:
// valid RFC3339 windows pass through, unparsable dates degrade to zero times,
// and an empty store returns an empty list.
func TestHeartbeatResults_WindowParsing(t *testing.T) {
	h, devID := setupHBHandler(t)

	rw := httptest.NewRecorder()
	h.ListResults(rw, reqWithBodyParams(http.MethodGet,
		"/x?start_date=2026-01-01T00:00:00Z&end_date=2026-12-31T23:59:59Z", "",
		map[string]string{"id": strconv.FormatInt(devID, 10)}))
	require.Equal(t, http.StatusOK, rw.Code)
	require.Contains(t, rw.Body.String(), `"results":[]`)

	// Unparsable dates degrade to zero times (no 400).
	rw = httptest.NewRecorder()
	h.ListResults(rw, reqWithBodyParams(http.MethodGet, "/x?start_date=yesterday&end_date=soon", "",
		map[string]string{"id": strconv.FormatInt(devID, 10)}))
	require.Equal(t, http.StatusOK, rw.Code)

	// Bad device id / pagination → 400.
	rw = httptest.NewRecorder()
	h.ListResults(rw, reqWithBodyParams(http.MethodGet, "/x", "", map[string]string{"id": "abc"}))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	rw = httptest.NewRecorder()
	h.ListResults(rw, httptest.NewRequest(http.MethodGet, "/x?limit=zzz", nil))
	require.Equal(t, http.StatusBadRequest, rw.Code)
	_ = devID
}
