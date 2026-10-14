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
	require.Equal(t, false, byMAC["aa:bb:cc:dd:ee:03"]["stp_root"], "a downstream bridge is not it")
	require.Equal(t, false, byMAC["aa:bb:cc:dd:ee:04"]["stp_root"], "no STP facts = not root, never null")
}

// The multi-homed presence a node carries must name its segments (#556): a
// chip reading "#2" answers nothing. Every presence entry carries the
// network's name + CIDR alongside the address, so the node card can render
// "lan-63 · 192.0.2.0/24 · 192.0.2.5" without a second round-trip.
func TestTopologyGraph_PresenceCarriesSegmentNames(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	exec := func(q string, args ...any) {
		_, err := conn.Exec(q, args...)
		require.NoError(t, err)
	}
	exec(`INSERT INTO networks (name, cidr) VALUES ('lan-a', '192.0.2.0/24')`)
	exec(`INSERT INTO networks (name, cidr) VALUES ('lan-b', '198.51.100.0/24')`)
	// The bridge: one device row (home lan-a), present in BOTH segments —
	// exactly the cross-segment link point the graph must be able to name.
	exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid, network_id)
		VALUES ('r68s-bridge', 'router', '192.0.2.1', 'aa:bb:cc:dd:ee:10', 'online', 'seed-bridge', 1)`)
	exec(`INSERT INTO device_network_presence (device_id, network_id, ip_address, vantage, first_seen, last_seen)
		VALUES (1, 1, '192.0.2.1', '', '2026-10-13 00:00:00', '2026-10-13 00:05:00')`)
	exec(`INSERT INTO device_network_presence (device_id, network_id, ip_address, vantage, first_seen, last_seen)
		VALUES (1, 2, '198.51.100.1', 'agent-lan-b', '2026-10-13 00:00:00', '2026-10-13 00:05:00')`)

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
		Nodes []presenceNode `json:"nodes"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	var bridge *presenceNode
	for i := range body.Nodes {
		if body.Nodes[i].MACAddress == "aa:bb:cc:dd:ee:10" {
			bridge = &body.Nodes[i]
		}
	}
	require.NotNil(t, bridge, "bridge device present in the graph")
	require.Len(t, bridge.Networks, 2, "the multi-homed fact: both segments")
	byNet := map[int64]presenceEntry{}
	for _, pn := range bridge.Networks {
		byNet[pn.NetworkID] = pn
	}
	require.Equal(t, "lan-a", byNet[1].Name, "presence names its segment")
	require.Equal(t, "192.0.2.0/24", byNet[1].CIDR)
	require.Equal(t, "192.0.2.1", byNet[1].IPAddress)
	require.Equal(t, "lan-b", byNet[2].Name)
	require.Equal(t, "198.51.100.0/24", byNet[2].CIDR)
	require.Equal(t, "agent-lan-b", byNet[2].Vantage)
}

// presenceEntry mirrors one topoNetwork on the wire (#556 test fixture).
type presenceEntry struct {
	NetworkID int64  `json:"network_id"`
	Name      string `json:"name"`
	CIDR      string `json:"cidr"`
	IPAddress string `json:"ip_address"`
	Vantage   string `json:"vantage"`
}

type presenceNode struct {
	MACAddress string          `json:"mac_address"`
	Networks   []presenceEntry `json:"networks"`
}

// TestTopologyGraph_EdgeLastSeen pins #585: every edge family carries its
// last_seen freshness on the wire — neighbor-derived, speaks-with, and
// route-table materialized edges — so the UI can fade ghost adjacencies.
func TestTopologyGraph_EdgeLastSeen(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Exec(`INSERT INTO devices (id, name, type, ip_address, mac_address, status, device_uuid)
		VALUES (1, 'sw', 'switch', '10.0.0.2', 'aa:bb:cc:dd:ee:01', 'online', 't585-sw'),
		       (2, 'dev', 'pc', '10.0.0.3', 'aa:bb:cc:dd:ee:02', 'online', 't585-dev'),
		       (3, 'peer', 'pc', '10.0.0.4', 'aa:bb:cc:dd:ee:03', 'online', 't585-peer')`)
	require.NoError(t, err)
	// Neighbor edge, refreshed an hour ago (stale by the UI's 10min rule).
	_, err = conn.Exec(`INSERT INTO device_neighbors (device_id, neighbor_mac, protocol, local_port, first_seen, last_seen)
		VALUES (1, 'aa:bb:cc:dd:ee:02', 'LLDP', 'gi1/0/1', datetime('now','-3 hours'), datetime('now','-1 hour'))`)
	require.NoError(t, err)
	// Speaks-with edge, fresh.
	_, err = conn.Exec(`INSERT INTO device_speaks_with (device_id, peer_ip, peer_device_id, bytes_in, bytes_out, first_seen, last_seen)
		VALUES (2, '10.0.0.4', 3, 100, 200, datetime('now','-1 hour'), datetime('now','-1 minute'))`)
	require.NoError(t, err)
	// Materialized route-table edge, refreshed 30 minutes ago.
	_, err = conn.Exec(`INSERT INTO topology_edges (from_device_id, to_device_id, edge_type, via_protocol, confidence, first_seen, last_seen)
		VALUES (1, 3, 'l3', 'route-table', 0.8, datetime('now','-2 hours'), datetime('now','-30 minutes'))`)
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
		Edges []struct {
			Protocol string `json:"protocol"`
			LastSeen string `json:"last_seen"`
		} `json:"edges"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	seen := map[string]string{}
	for _, e := range body.Edges {
		seen[e.Protocol] = e.LastSeen
	}
	require.Contains(t, seen, "LLDP")
	require.NotEmpty(t, seen["LLDP"], "neighbor edge must carry last_seen")
	require.Contains(t, seen, "speaks-with")
	require.NotEmpty(t, seen["speaks-with"], "speaks-with edge must carry last_seen")
	require.Contains(t, seen, "route-table")
	require.NotEmpty(t, seen["route-table"], "materialized route edge must carry last_seen")
}
