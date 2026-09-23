// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

// TestDeriveTopologyEdges seeds two devices joined by an LLDP neighbor row and
// verifies the finalize step materializes the device↔device edge; an
// unidentified neighbor (no matching MAC) stays out; a NULL network scope is a
// no-op; re-running refreshes rather than duplicating.
func TestDeriveTopologyEdges(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	rn := New(nil, queries, conn, nil, 0, nil)
	rn.SetRepo(store.NewSQLiteRepository(conn, store.Options{}, nil))

	ctx := context.Background()
	net, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "edge-net"})
	require.NoError(t, err)

	seed := func(name, ip, mac string) int64 {
		res, err := conn.Exec(`INSERT INTO devices (device_uuid, name, ip_address, mac_address, status, network_id)
			VALUES (?, ?, ?, ?, 'online', ?)`, "uuid-te-"+name, name, ip, mac, net.ID)
		require.NoError(t, err)
		id, _ := res.LastInsertId()
		return id
	}
	swID := seed("edge-sw", "10.30.0.1", "00:11:22:33:44:55")
	apID := seed("edge-ap", "10.30.0.2", "00:11:22:33:44:66")

	// sw sees ap over LLDP (resolved neighbor); sw also hears an unknown MAC.
	_, err = conn.Exec(`INSERT INTO device_neighbors (device_id, neighbor_mac, protocol, local_port, remote_port, network_id)
		VALUES (?, '00:11:22:33:44:66', 'lldp', 'ge-1', 'eth0', ?)`, swID, net.ID)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO device_neighbors (device_id, neighbor_mac, protocol, network_id)
		VALUES (?, 'de:ad:00:00:00:ff', 'cdp', ?)`, swID, net.ID)
	require.NoError(t, err)

	rn.deriveTopologyEdges(ctx, sql.NullInt64{Int64: net.ID, Valid: true})

	// Exactly one materialized edge: sw → ap (the ghost neighbor doesn't join).
	var count int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM topology_edges`).Scan(&count))
	require.Equal(t, 1, count)
	var from, to sql.NullInt64
	var protoStr string
	require.NoError(t, conn.QueryRow(
		`SELECT from_device_id, to_device_id, via_protocol FROM topology_edges`).Scan(&from, &to, &protoStr))
	require.Equal(t, swID, from.Int64)
	require.Equal(t, apID, to.Int64)
	require.Equal(t, "lldp", protoStr)

	// A re-run refreshes instead of duplicating.
	rn.deriveTopologyEdges(ctx, sql.NullInt64{Int64: net.ID, Valid: true})
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM topology_edges`).Scan(&count))
	require.Equal(t, 1, count)

	// NULL network scope → no-op (no query runs).
	rn.deriveTopologyEdges(ctx, sql.NullInt64{})
}
