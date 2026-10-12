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
	"database/sql"
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

func window2Server(t *testing.T) (*httptest.Server, string, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	middleware.SetJWTAuth("test-secret-key-for-tests")
	topo := handler.NewTopologyHandler(sqldb.New(conn))
	ifaces := handler.NewDeviceInterfacesHandler(sqldb.New(conn))
	r := chi.NewRouter()
	r.Route("/api/v1/devices/{id}/interfaces", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", ifaces.ListByDevice)
	})
	r.Route("/api/v1/topology", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", topo.Graph)
	})
	ta := jwtauth.New("HS256", []byte("test-secret-key-for-tests"), nil)
	_, token, err := ta.Encode(map[string]interface{}{"user_id": int64(1), "role": "admin"})
	require.NoError(t, err)
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return server, token, conn
}

// The interface census endpoint (#529): ordered by ifIndex, full port facts.
func TestDeviceInterfaces_ListByDevice(t *testing.T) {
	server, token, conn := window2Server(t)

	get := func(url string) map[string]interface{} {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.Config.Handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body
	}

	body := get("/api/v1/devices/999/interfaces")
	require.EqualValues(t, 0, body["total"], "unknown device yields an empty census")

	// Seed via the server's own DB (the handler reads sqlc).
	res, err := conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid)
		VALUES ('sw', 'switch', '10.0.0.1', 'aa:bb:cc:dd:ee:01', 'online', 'seed-ifsw')`)
	require.NoError(t, err)
	devID, _ := res.LastInsertId()
	_, err = conn.Exec(`INSERT INTO device_interfaces (device_id, if_index, if_name, if_descr, mac_address, ip_address, speed, first_seen, last_seen)
		VALUES (?, 2, 'eth1', 'Ethernet1', 'aa:bb:cc:dd:ee:02', '10.0.1.1', 1000, '2026-10-12T00:00:00Z', '2026-10-12T01:00:00Z'),
		       (?, 1, 'eth0', 'Ethernet0', 'aa:bb:cc:dd:ee:01', '10.0.0.1', 1000, '2026-10-12T00:00:00Z', '2026-10-12T01:00:00Z')`,
		devID, devID)
	require.NoError(t, err)

	body = get("/api/v1/devices/" + strconv.FormatInt(devID, 10) + "/interfaces")
	require.EqualValues(t, 2, body["total"])
	list := body["interfaces"].([]interface{})
	first := list[0].(map[string]interface{})
	require.EqualValues(t, 1, first["if_index"], "ordered by ifIndex")
	require.Equal(t, "10.0.0.1", first["ip_address"])
	require.EqualValues(t, 1000, first["speed"])
}

// The topology graph unions route-table edges from topology_edges (#528):
// deduped against neighbor-derived edges, metadata carrying the destination
// subnet.
func TestTopologyGraph_RouteTableEdgesUnioned(t *testing.T) {
	server, token, conn := window2Server(t)

	var a, b int64
	res, _ := conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid)
		VALUES ('r1', 'router', '10.0.0.1', 'aa:bb:cc:dd:ee:01', 'online', 'seed-rte-a')`)
	a, _ = res.LastInsertId()
	res, _ = conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid)
		VALUES ('r2', 'router', '10.0.0.254', 'aa:bb:cc:dd:ee:fe', 'online', 'seed-rte-b')`)
	b, _ = res.LastInsertId()
	_, err := conn.Exec(`INSERT INTO topology_edges (from_device_id, to_device_id, edge_type, via_protocol, confidence, metadata, first_seen, last_seen)
		VALUES (?, ?, 'l3', 'route-table', 0.7, '{"dest_subnet":"172.16.0.0/12","next_hop":"10.0.0.254","route_proto":"ospf"}', '2026-10-12T00:00:00Z', '2026-10-12T01:00:00Z')`, a, b)
	require.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/topology", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Config.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var graph struct {
		Edges []map[string]interface{} `json:"edges"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &graph))
	var found bool
	for _, e := range graph.Edges {
		if e["protocol"] == "route-table" {
			found = true
			meta := e["metadata"].(map[string]interface{})
			require.Equal(t, "172.16.0.0/12", meta["dest_subnet"])
		}
	}
	require.True(t, found, "the route-table edge must render in the graph")
}
