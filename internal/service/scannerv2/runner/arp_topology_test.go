// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

func TestHexRouteToIP(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		{"0100A8C0", "192.168.0.1"}, // canonical little-endian example
		{"0101A8C0", "192.168.1.1"},
		{"0A00000A", "10.0.0.10"},
		{"", ""},           // too short
		{"0100A8", ""},     // 7 chars
		{"0100A8C0FF", ""}, // too long
		{"ZZ00A8C0", ""},   // non-hex bytes
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, hexRouteToIP(tc.hex), "input %q", tc.hex)
	}
}

func TestGuessGatewayFromARP(t *testing.T) {
	require.Equal(t, "192.168.63.1", guessGatewayFromARP(map[string]string{
		"192.168.63.20": "aa:bb:cc:dd:ee:20",
		"192.168.63.1":  "aa:bb:cc:dd:ee:01",
	}))
	// .1 on a different octet boundary does not count; no candidate → ""
	require.Equal(t, "10.0.0.1", guessGatewayFromARP(map[string]string{
		"10.0.0.1":  "aa:bb:cc:dd:ee:01",
		"10.0.0.53": "aa:bb:cc:dd:ee:53",
	}))
	require.Empty(t, guessGatewayFromARP(map[string]string{
		"192.168.63.20": "aa:bb:cc:dd:ee:20",
	}))
	require.Empty(t, guessGatewayFromARP(nil))
}

func TestReadARPFile_ParsesProcNetArpFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arp")
	require.NoError(t, os.WriteFile(path, []byte(`IP address       HW type     Flags       HW address            Mask     Device
192.168.63.1     0x1         0x2         AA:BB:CC:DD:EE:01   *        eth0
192.168.63.20    0x1         0x2         aa:bb:cc:dd:ee:20   *        eth0
192.168.63.99    0x1         0x0         00:00:00:00:00:00   *        eth0
shortline
`), 0o644))

	got, err := readARPFile(path)
	require.NoError(t, err)
	// MACs lowercased, zero/incomplete entries and malformed rows skipped
	require.Equal(t, map[string]string{
		"192.168.63.1":  "aa:bb:cc:dd:ee:01",
		"192.168.63.20": "aa:bb:cc:dd:ee:20",
	}, got)

	_, err = readARPFile(filepath.Join(dir, "missing"))
	require.Error(t, err)
}

func TestReadDefaultGatewayFrom_RouteTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	// Destination 00000000 = default route; gateway hex little-endian.
	// A non-default row comes first to prove it is skipped.
	require.NoError(t, os.WriteFile(path, []byte(`Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	RTT
eth1	0001A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
eth0	00000000	0101A8C0	0003	0	0	0	00000000	0	0	0
`), 0o644))

	require.Equal(t, "192.168.1.1", readDefaultGatewayFrom(path))

	// no default route → ""
	noDefault := filepath.Join(dir, "route2")
	require.NoError(t, os.WriteFile(noDefault, []byte("Iface\tDestination\tGateway\neth0\t0001A8C0\t0A000001\n"), 0o644))
	require.Empty(t, readDefaultGatewayFrom(noDefault))

	// unreadable file → ""
	require.Empty(t, readDefaultGatewayFrom(filepath.Join(dir, "missing")))
}

// TestInjectARPEdges drives the DB core of the ARP topology step with a
// fabricated gateway + scan reports: every scanned alive device except the
// gateway itself gets a device→gateway edge with protocol="ARP", and a repeat
// run updates last_seen instead of duplicating rows.
func TestInjectARPEdges(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	rn := New(nil, queries, conn, nil, 0, nil)
	rn.SetRepo(store.NewSQLiteRepository(conn, store.Options{}, nil))

	ctx := context.Background()
	net, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "arp-net"})
	require.NoError(t, err)
	nid := sql.NullInt64{Int64: net.ID, Valid: true}

	// Persist three devices: two plain hosts + the gateway itself (.1).
	gwMAC := "aa:bb:cc:dd:ee:01"
	for _, m := range []string{gwMAC, "aa:bb:cc:dd:ee:20", "aa:bb:cc:dd:ee:30"} {
		rn.applyDeviceBridge(ctx, reportFor("192.168.63."+m[len(m)-2:], "pc", "test-brand", m), nid, "")
	}

	reports := []scannerv2.HostReport{
		reportFor("192.168.63.1", "router", "test-brand", gwMAC),
		reportFor("192.168.63.20", "pc", "test-brand", "aa:bb:cc:dd:ee:20"),
		reportFor("192.168.63.30", "pc", "test-brand", "aa:bb:cc:dd:ee:30"),
		{Alive: false, IP: "192.168.63.99"}, // dead host: no edge
	}

	rn.injectARPEdges(ctx, nid, reports, "192.168.63.1", "AA:BB:CC:DD:EE:01")

	rows, err := conn.QueryContext(ctx,
		`SELECT d.mac_address, n.neighbor_mac, n.protocol FROM device_neighbors n JOIN devices d ON d.id = n.device_id`)
	require.NoError(t, err)
	defer rows.Close()
	var edges []struct{ deviceMAC, neighborMAC, protocol string }
	for rows.Next() {
		var e struct{ deviceMAC, neighborMAC, protocol string }
		require.NoError(t, rows.Scan(&e.deviceMAC, &e.neighborMAC, &e.protocol))
		edges = append(edges, e)
	}
	require.NoError(t, rows.Err())

	// gateway itself must NOT point at itself; both hosts get exactly one edge
	require.Len(t, edges, 2)
	seen := map[string]bool{}
	for _, e := range edges {
		require.Equal(t, gwMAC, e.neighborMAC)
		require.Equal(t, "ARP", e.protocol)
		seen[e.deviceMAC] = true
	}
	require.True(t, seen["aa:bb:cc:dd:ee:20"])
	require.True(t, seen["aa:bb:cc:dd:ee:30"])

	// a second pass refreshes last_seen (upsert) instead of duplicating
	rn.injectARPEdges(ctx, nid, reports, "192.168.63.1", "AA:BB:CC:DD:EE:01")
	var count int
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_neighbors`).Scan(&count))
	require.Equal(t, 2, count)
}

// TestInjectARPTopology_NoNetworkScope: without a resolved network_id the
// step is a no-op (edges can't be partitioned to a network).
func TestInjectARPTopology_NoNetworkScope(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	rn := New(nil, queries, conn, nil, 0, nil)

	rn.injectARPTopology(context.Background(), sql.NullInt64{}, []scannerv2.HostReport{
		reportFor("192.168.63.20", "pc", "test-brand", "aa:bb:cc:dd:ee:20"),
	})

	var count int
	require.NoError(t, conn.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM device_neighbors`).Scan(&count))
	require.Zero(t, count)
}
