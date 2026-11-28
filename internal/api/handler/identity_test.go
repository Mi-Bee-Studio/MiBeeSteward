// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not accommodate;
// see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/domain"
	identitysvc "mibee-steward/internal/service/identity"
	"mibee-steward/internal/testutil"
)

func identityRouter(h *handler.IdentityHandler) http.Handler {
	r := chi.NewRouter()
	r.Get("/api/v1/identity/candidates", h.ListCandidates)
	r.Get("/api/v1/devices/{id}/identity", h.GetDeviceIdentity)
	return r
}

func identityRequest(t *testing.T, router http.Handler, target string, scope domain.Scope) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if !scope.IsGlobal() || len(scope.NetworkIDs) > 0 {
		req = req.WithContext(context.WithValue(req.Context(), domain.ContextKeyUserScope, scope))
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	return rec.Code, body
}

func TestIdentityHandlerCandidatesAndDeviceProjection(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = conn.Exec(`INSERT INTO networks (name, cidr) VALUES ('lan', '192.0.2.0/24')`)
	require.NoError(t, err)
	var networkID int64
	require.NoError(t, conn.QueryRow(`SELECT id FROM networks WHERE name='lan'`).Scan(&networkID))
	for _, d := range []struct{ name, uuid, mac string }{
		{"identity-a", "identity-a", "aa:bb:cc:dd:ee:01"},
		{"identity-b", "identity-b", "aa:bb:cc:dd:ee:02"},
	} {
		_, err = conn.Exec(`INSERT INTO devices
			(device_uuid, name, type, brand, model, ip_address, mac_address, serial_number,
			 network_id, status, first_seen, last_seen, scan_attributes)
			VALUES (?, ?, 'server', 'Acme', 'X', ?, ?, 'SN-1', ?, 'online',
				'2026-11-27T08:00:00Z', '2026-11-28T08:00:00Z', '{"hostname":"Identity-Host.example"}')`,
			d.uuid, d.name, "192.0.2."+map[string]string{"identity-a": "10", "identity-b": "11"}[d.name], d.mac, networkID)
		require.NoError(t, err)
	}
	var deviceID int64
	require.NoError(t, conn.QueryRow(`SELECT id FROM devices WHERE device_uuid='identity-a'`).Scan(&deviceID))

	h := handler.NewIdentityHandler(identitysvc.NewService(conn))
	router := identityRouter(h)
	code, body := identityRequest(t, router, "/api/v1/identity/candidates?limit=9999&device_ids="+identityID(deviceID), domain.Scope{Global: true})
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, float64(500), body["limit"], "over-max pagination follows the shared clamp contract")
	require.Equal(t, float64(1), body["total"])
	candidates := body["candidates"].([]any)
	require.Len(t, candidates, 1)
	candidate := candidates[0].(map[string]any)
	require.Equal(t, "high", candidate["confidence"])
	require.Equal(t, true, candidate["temporal_overlap"])
	require.NotEmpty(t, candidate["evidence"])

	code, body = identityRequest(t, router, "/api/v1/devices/"+identityID(deviceID)+"/identity", domain.Scope{NetworkIDs: []int64{networkID}})
	require.Equal(t, http.StatusOK, code, body)
	device := body["device"].(map[string]any)
	require.Equal(t, float64(deviceID), device["id"])
	require.Len(t, body["candidates"], 1)

	code, body = identityRequest(t, router, "/api/v1/devices/99999/identity", domain.Scope{Global: true})
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, "device not found", body["error"])
}

func TestIdentityHandlerRejectsInvalidQueries(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	router := identityRouter(handler.NewIdentityHandler(identitysvc.NewService(conn)))

	for _, target := range []string{
		"/api/v1/identity/candidates?limit=-1",
		"/api/v1/identity/candidates?limit=nope",
		"/api/v1/identity/candidates?offset=-1",
		"/api/v1/identity/candidates?network_id=0",
		"/api/v1/identity/candidates?device_ids=1,nope",
		"/api/v1/identity/candidates?device_ids=" + repeatIDList(201),
		"/api/v1/identity/candidates?min_confidence=ultra",
		"/api/v1/devices/not-a-number/identity",
	} {
		t.Run(target, func(t *testing.T) {
			code, body := identityRequest(t, router, target, domain.Scope{Global: true})
			require.Equal(t, http.StatusBadRequest, code, body)
			require.Contains(t, body, "error")
		})
	}
}

func TestIdentityHandlerDatabaseFailureIsInternalError(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	router := identityRouter(handler.NewIdentityHandler(identitysvc.NewService(conn)))
	code, body := identityRequest(t, router, "/api/v1/identity/candidates", domain.Scope{Global: true})
	require.Equal(t, http.StatusInternalServerError, code)
	require.Equal(t, "failed to compute identity candidates", body["error"])
	code, body = identityRequest(t, router, "/api/v1/devices/1/identity", domain.Scope{Global: true})
	require.Equal(t, http.StatusInternalServerError, code)
	require.Equal(t, "failed to compute device identity", body["error"])
}

func identityID(id int64) string {
	return strconv.FormatInt(id, 10)
}

func repeatIDList(n int) string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	return strings.Join(ids, ",")
}
