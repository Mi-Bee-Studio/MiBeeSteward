// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"

	handler "mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// The subnets table is written by every scan finalize (runner/subnets.go) but
// had no consumer (#503). GET /api/v1/subnets exposes it read-only with the
// same envelope shape as /networks/{id}/vlans ({subnets, total}).

func newSubnetTestServer(t *testing.T, conn *sql.DB) *httptest.Server {
	t.Helper()
	middleware.SetJWTAuth("test-secret-key-for-tests")
	subnetHandler := handler.NewSubnetHandler(sqldb.New(conn))
	r := chi.NewRouter()
	r.Route("/api/v1/subnets", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", subnetHandler.List)
	})
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return server
}

// subnetTestToken mints an admin JWT against the same secret the middleware
// authenticator was initialized with. The mini-router intentionally mounts no
// /auth/login (that route belongs to the user-handler fixture), so the token
// is signed directly instead of logging in.
func subnetTestToken(t *testing.T) string {
	t.Helper()
	ta := jwtauth.New("HS256", []byte("test-secret-key-for-tests"), nil)
	_, token, err := ta.Encode(map[string]interface{}{"user_id": int64(1), "role": "admin"})
	require.NoError(t, err)
	return token
}

func TestSubnetHandler_List(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	netRes, err := conn.Exec(`INSERT INTO networks (name) VALUES ('lan-a')`)
	require.NoError(t, err)
	netA, err := netRes.LastInsertId()
	require.NoError(t, err)
	netRes2, err := conn.Exec(`INSERT INTO networks (name) VALUES ('lan-b')`)
	require.NoError(t, err)
	netB, err := netRes2.LastInsertId()
	require.NoError(t, err)

	gw := "192.168.2.1"
	vlan := int64(7)
	_, err = conn.Exec(`INSERT INTO subnets (network_id, cidr, vlan_id, gateway, metadata, first_seen, last_seen)
		VALUES (?, '10.30.0.0/16', ?, ?, '{}', '2026-10-10T12:00:00Z', '2026-10-10T12:00:00Z')`, netB, vlan, gw)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO subnets (network_id, cidr, metadata, first_seen, last_seen)
		VALUES (?, '192.168.2.0/24', '{}', '2026-10-10T12:00:00Z', '2026-10-10T12:00:00Z')`, netA)
	require.NoError(t, err)

	server := newSubnetTestServer(t, conn)
	token := subnetTestToken(t)

	// All networks: 2 rows ordered by cidr, nullable fields marshaled.
	resp := authGet(t, server.URL+"/api/v1/subnets", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]interface{}
	decodeJSON(t, resp, &body)
	require.Equal(t, float64(2), body["total"])
	rows := body["subnets"].([]interface{})
	first := rows[0].(map[string]interface{})
	require.Equal(t, "10.30.0.0/16", first["cidr"])
	require.Equal(t, "192.168.2.1", first["gateway"])
	require.Equal(t, float64(7), first["vlan_id"])

	// Filter by network: only that network's rows.
	resp = authGet(t, server.URL+"/api/v1/subnets?network_id="+strconv.FormatInt(netA, 10), token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &body)
	require.Equal(t, float64(1), body["total"])
	require.Equal(t, "192.168.2.0/24", body["subnets"].([]interface{})[0].(map[string]interface{})["cidr"])
}

func TestSubnetHandler_EmptyList(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	server := newSubnetTestServer(t, conn)
	resp := authGet(t, server.URL+"/api/v1/subnets", subnetTestToken(t))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]interface{}
	decodeJSON(t, resp, &body)
	require.Equal(t, float64(0), body["total"])
	require.NotNil(t, body["subnets"])
}
