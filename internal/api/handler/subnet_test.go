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
	"context"
	"database/sql"
	"encoding/json"
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
	"mibee-steward/internal/domain"
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

// TestSubnetHandler_ScopeEnforcement pins the #536 fix: the scope
// intersection applies on EVERY path, including an explicit ?network_id= the
// caller holds no grant for (deny = empty set, topology-graph semantics).
// The mini-router mounts no NetworkScope middleware (that is the gap the
// review found: the vulnerable branch had no test), so scopes are injected
// directly into the request context.
func TestSubnetHandler_ScopeEnforcement(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	var netA, netB int64
	for _, name := range []string{"lan-a", "lan-b"} {
		res, err := conn.Exec(`INSERT INTO networks (name) VALUES (?)`, name)
		require.NoError(t, err)
		id, _ := res.LastInsertId()
		if name == "lan-a" {
			netA = id
		} else {
			netB = id
		}
	}
	for _, net := range []int64{netA, netB} {
		_, err := conn.Exec(`INSERT INTO subnets (network_id, cidr, metadata, first_seen, last_seen)
			VALUES (?, '10.30.0.0/24', '{}', '2026-10-10T12:00:00Z', '2026-10-10T12:00:00Z')`, net)
		require.NoError(t, err)
	}

	h := handler.NewSubnetHandler(sqldb.New(conn))
	scoped := func(ids ...int64) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), domain.ContextKeyUserScope,
				domain.Scope{NetworkIDs: ids}))
		}
	}
	global := func(r *http.Request) *http.Request { return r }

	cases := []struct {
		name      string
		query     string
		inject    func(*http.Request) *http.Request
		wantTotal int
	}{
		// 1: the #536 regression — restricted + unauthorized explicit id
		// must DENY (empty), not fall back to unfiltered.
		{"restricted + unauthorized network_id -> deny", "?network_id=" + strconv.FormatInt(netB, 10), scoped(netA), 0},
		{"restricted + granted network_id -> only that network", "?network_id=" + strconv.FormatInt(netA, 10), scoped(netA), 1},
		{"restricted + no param -> granted aggregation", "", scoped(netA), 1},
		{"global + no param -> all", "", global, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := tc.inject(httptest.NewRequest(http.MethodGet, "/api/v1/subnets"+tc.query, nil))
			h.List(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
			var body struct {
				Total   int              `json:"total"`
				Subnets []map[string]any `json:"subnets"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tc.wantTotal, body.Total)
		})
	}
}
