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
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// The topology graph's root detection stops being a frontend heuristic when a
// bridge reports "I am the STP root" (#525): the node set carries the fact as
// a boolean extracted from scan_attributes.stp.

func TestTopologyGraph_STPRootFact(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	// A switch whose dot1dStp walk recorded root facts: it IS the root.
	_, err = conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status,
		device_uuid, scan_attributes) VALUES ('core-sw', 'switch', '10.0.0.2', 'aa:bb:cc:dd:ee:02',
		'online', 'seed-stp-root', ?)`,
		`{"stp":{"bridge_mac":"aa:bb:cc:dd:ee:02","root_bridge_mac":"aa:bb:cc:dd:ee:02","is_root":true,"ports":"port1=designated,port2=designated"}}`)
	require.NoError(t, err)
	// A downstream switch: knows the root, is not it.
	_, err = conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status,
		device_uuid, scan_attributes) VALUES ('acc-sw', 'switch', '10.0.0.3', 'aa:bb:cc:dd:ee:03',
		'online', 'seed-stp-acc', ?)`,
		`{"stp":{"bridge_mac":"aa:bb:cc:dd:ee:03","root_bridge_mac":"aa:bb:cc:dd:ee:02","is_root":false,"ports":"port1=root"}}`)
	require.NoError(t, err)
	// An ordinary device with no STP facts at all.
	_, err = conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid)
		VALUES ('laptop', 'pc', '10.0.0.4', 'aa:bb:cc:dd:ee:04', 'online', 'seed-stp-none')`)
	require.NoError(t, err)

	middleware.SetJWTAuth("test-secret-key-for-tests")
	h := handler.NewTopologyHandler(sqldb.New(conn))
	r := chi.NewRouter()
	r.Route("/api/v1/topology", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", h.Graph)
	})
	ta := jwtauth.New("HS256", []byte("test-secret-key-for-tests"), nil)
	_, token, err := ta.Encode(map[string]interface{}{"user_id": int64(1), "role": "admin"})
	require.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/topology", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Nodes []map[string]interface{} `json:"nodes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	byMAC := map[string]map[string]interface{}{}
	for _, n := range body.Nodes {
		byMAC[n["mac_address"].(string)] = n
	}
	require.Equal(t, true, byMAC["aa:bb:cc:dd:ee:02"]["stp_root"], "the root bridge reports the fact")
	require.Equal(t, false, byMAC["aa:bb:cc:dd:ee:03"]["stp_root"], "a downstream bridge is not the root")
	require.Equal(t, false, byMAC["aa:bb:cc:dd:ee:04"]["stp_root"], "no STP facts = not root, never null")
}
