// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// device_interfaces (#529): the per-port census upserted from IF-MIB walks.
func TestRecordInterfaces_UpsertPerIfIndex(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	devID := seedDeviceRow(t, repo.db, "10.0.0.1", "aa:bb:cc:dd:ee:01", sql.NullInt64{})

	specs := []scannerv2.InterfaceSpec{
		{IfIndex: 1, IfName: "eth0", IfDescr: "eth0", MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.1", Speed: 1000},
		{IfIndex: 2, IfName: "eth1", MAC: "aa:bb:cc:dd:ee:02", IP: "10.0.1.1", Speed: 1000},
	}
	require.NoError(t, repo.recordInterfaces(ctx, devID, specs))

	// Re-walk: names refresh, still one row per ifIndex; a vanished port is
	// left in place (last_seen freezes - history, not deletion).
	specs2 := []scannerv2.InterfaceSpec{
		{IfIndex: 1, IfName: "eth0-renamed", MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.1", Speed: 1000},
	}
	require.NoError(t, repo.recordInterfaces(ctx, devID, specs2))

	var n int
	require.NoError(t, repo.db.QueryRow(
		`SELECT COUNT(*) FROM device_interfaces WHERE device_id = ?`, devID).Scan(&n))
	require.EqualValues(t, 2, n)
	var name string
	require.NoError(t, repo.db.QueryRow(
		`SELECT if_name FROM device_interfaces WHERE device_id = ? AND if_index = 1`, devID).Scan(&name))
	require.Equal(t, "eth0-renamed", name)
}

// Route-table edges (#528): each collected route whose next hop resolves to a
// KNOWN device materializes a topology edge (router -> next hop), carrying the
// destination subnet in metadata. Unresolvable next hops are skipped (they
// render as nothing today; the raw evidence still lives in service_evidence).
func TestRecordRoutes_EdgesToNextHopDevices(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	routerID := seedDeviceRow(t, repo.db, "10.0.0.1", "aa:bb:cc:dd:ee:01", sql.NullInt64{})
	upstreamID := seedDeviceRow(t, repo.db, "10.0.0.254", "aa:bb:cc:dd:ee:fe", sql.NullInt64{})
	_ = upstreamID

	routes := []scannerv2.RouteSpec{
		{DestCIDR: "172.16.0.0/12", NextHop: "10.0.0.254", IfIndex: 1, Proto: "static"},
		{DestCIDR: "192.168.50.0/24", NextHop: "10.0.0.253", Proto: "ospf"},       // no device at .253
		{DestCIDR: "0.0.0.0/0", NextHop: "10.0.0.254", IfIndex: 2, Proto: "dhcp"}, // second route, same hop
	}
	require.NoError(t, repo.recordRoutes(ctx, routerID, routes))

	var n int
	require.NoError(t, repo.db.QueryRow(
		`SELECT COUNT(*) FROM topology_edges WHERE via_protocol = 'route-table'`).Scan(&n))
	// Two routes share the hop device: the UNIQUE(from,to,edge_type) upsert
	// keeps ONE edge; the richer metadata (more specific subnet) survives.
	require.EqualValues(t, 1, n)

	var toID int64
	var meta string
	require.NoError(t, repo.db.QueryRow(
		`SELECT to_device_id, metadata FROM topology_edges WHERE via_protocol = 'route-table'`).Scan(&toID, &meta))
	require.Equal(t, upstreamID, toID)
	require.Contains(t, meta, "172.16.0.0/12", "the more specific subnet wins the metadata")
	require.Contains(t, meta, "\"next_hop\"")
}

func TestRecordRoutes_SelfNextHopSkipped(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	devID := seedDeviceRow(t, repo.db, "10.0.0.1", "aa:bb:cc:dd:ee:01", sql.NullInt64{})
	require.NoError(t, repo.recordRoutes(ctx, devID, []scannerv2.RouteSpec{
		{DestCIDR: "10.0.5.0/24", NextHop: "10.0.0.1", Proto: "local"}, // the router itself
	}))
	var n int
	require.NoError(t, repo.db.QueryRow(`SELECT COUNT(*) FROM topology_edges`).Scan(&n))
	require.Zero(t, n)
}
