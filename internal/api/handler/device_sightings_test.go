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
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// The sightings endpoint (#527): newest-first history, vantage filter, and
// the see_count/last_seen upsert semantics the store guarantees.
func TestDeviceSightings_ListAndVantageFilter(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	res, err := conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid)
		VALUES ('roamer', 'pc', '10.0.0.7', 'aa:bb:cc:dd:ee:07', 'online', 'seed-sight')`)
	require.NoError(t, err)
	devID, _ := res.LastInsertId()

	seed := []string{
		`INSERT INTO device_sightings (device_id, ip_address, mac_address, network_id, vantage, source, first_seen, last_seen, see_count)
		 VALUES (?, '10.0.0.7', 'aa:bb:cc:dd:ee:07', NULL, '', 'scan', '2026-10-01T00:00:00Z', '2026-10-12T08:00:00Z', 9)`,
		`INSERT INTO device_sightings (device_id, ip_address, mac_address, network_id, vantage, source, first_seen, last_seen, see_count)
		 VALUES (?, '10.0.0.99', 'aa:bb:cc:dd:ee:07', NULL, 'agent-lan-63', 'scan', '2026-10-10T00:00:00Z', '2026-10-11T00:00:00Z', 2)`,
	}
	for _, q := range seed {
		_, err := conn.Exec(q, devID)
		require.NoError(t, err)
	}

	middleware.SetJWTAuth("test-secret-key-for-tests")
	h := handler.NewDeviceSightingsHandler(sqldb.New(conn))
	r := chi.NewRouter()
	r.Route("/api/v1/devices/{id}/sightings", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", h.ListByDevice)
	})
	ta := jwtauth.New("HS256", []byte("test-secret-key-for-tests"), nil)
	_, token, err := ta.Encode(map[string]interface{}{"user_id": int64(1), "role": "admin"})
	require.NoError(t, err)

	get := func(url string) []map[string]any {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var body struct {
			Sightings []map[string]any `json:"sightings"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body.Sightings
	}

	all := get("/api/v1/devices/" + strconv.FormatInt(devID, 10) + "/sightings")
	require.Len(t, all, 2)
	require.Equal(t, "10.0.0.7", all[0]["ip_address"], "newest first")
	require.EqualValues(t, 9, all[0]["see_count"])
	require.Empty(t, all[0]["vantage"], "center-local vantage omits from JSON")

	filtered := get("/api/v1/devices/" + strconv.FormatInt(devID, 10) + "/sightings?vantage=agent-lan-63")
	require.Len(t, filtered, 1)
	require.Equal(t, "10.0.0.99", filtered[0]["ip_address"])
	require.Equal(t, "agent-lan-63", filtered[0]["vantage"])
}
