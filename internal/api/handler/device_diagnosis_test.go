// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/service/diagnostics"
	"mibee-steward/internal/testutil"
)

// The diagnosis endpoint (#761): the classified verdict with the evidence
// chain, computed on demand over the persisted scan facts. Pinned against the
// field incident shape: many sighted addresses, none answering a scan.
func TestDeviceDiagnosis_VerdictAndEvidence(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	res, err := conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid, scan_attributes)
		VALUES ('ghost-box', 'iot', '10.0.0.131', '7c:83:34:00:00:2a', 'offline', 'seed-diag',
				'{"hostname":"ghost-box","mac":"7c:83:34:00:00:2a"}')`)
	require.NoError(t, err)
	ghostID, _ := res.LastInsertId()

	sightings := []string{"10.0.0.131", "10.0.0.42", "10.0.0.100", "10.0.0.107"}
	for _, ip := range sightings {
		_, err := conn.Exec(`INSERT INTO device_sightings
			(device_id, ip_address, mac_address, network_id, vantage, source, first_seen, last_seen, see_count)
			VALUES (?, ?, '7c:83:34:00:00:2a', NULL, 'agent-a', 'scan', '2026-11-19T08:00:00Z', '2026-11-19T12:00:00Z', 5)`,
			ghostID, ip)
		require.NoError(t, err)
	}
	// No scan_snapshots rows: none of the addresses ever answered a scan.

	middleware.SetJWTAuth("test-secret-key-for-tests")
	h := handler.NewDeviceDiagnosisHandler(diagnostics.NewService(conn))
	r := chi.NewRouter()
	r.Route("/api/v1/devices/{id}/diagnosis", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", h.Get)
	})
	ta := jwtauth.New("HS256", []byte("test-secret-key-for-tests"), nil)
	_, token, err := ta.Encode(map[string]interface{}{"user_id": int64(1), "role": "admin"})
	require.NoError(t, err)

	do := func(id int64) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/devices/"+strconv.FormatInt(id, 10)+"/diagnosis", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return rec.Code, body
	}

	code, body := do(ghostID)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "anomaly", body["status"])
	require.Equal(t, "stale_arp_scan_artifact", body["classification"])
	require.Equal(t, "high", body["confidence"])
	require.NotEmpty(t, body["summary"])

	addrs, ok := body["addresses"].([]any)
	require.True(t, ok)
	require.Len(t, addrs, 4)

	findings, ok := body["findings"].([]any)
	require.True(t, ok)
	require.Len(t, findings, 1)
	f := findings[0].(map[string]any)
	require.Equal(t, "critical", f["severity"])
	ev, ok := f["evidence"].([]any)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(ev), 5, "1 sighting fact + 4 dead-address facts + offline")

	// Unknown device maps to 404.
	code, _ = do(99999)
	require.Equal(t, http.StatusNotFound, code)
}
