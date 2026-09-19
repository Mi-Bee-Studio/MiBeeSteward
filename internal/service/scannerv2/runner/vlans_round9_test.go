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
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

// TestRecordVLANs pins the two evidence→vlans paths (#273): "vlan" evidence
// (static-table walk) fills names, "neighbor" vlan_tag marks tags carrying
// traffic; a single-VLAN network also gets its subnet linked to that VLAN.
func TestRecordVLANs(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	rn := New(nil, queries, conn, nil, 0, nil)
	rn.SetRepo(store.NewSQLiteRepository(conn, store.Options{}, nil))

	ctx := context.Background()
	net, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "vlan-net"})
	require.NoError(t, err)
	netID := sql.NullInt64{Int64: net.ID, Valid: true}

	// A subnet row for the single-VLAN link assertion.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO subnets (network_id, cidr, gateway) VALUES (?, '10.9.0.0/24', '10.9.0.1')`, net.ID)
	require.NoError(t, err)

	reports := []scannerv2.HostReport{{
		IP: "10.9.0.1", Alive: true,
		Evidence: []scannerv2.Evidence{
			{Kind: "vlan", RawData: map[string]string{"vlan_tag": "42", "vlan_name": "mgmt"}},
			// A tag seen only via FDB traffic (no static name) still records.
			{Kind: "neighbor", RawData: map[string]string{"vlan_tag": "7", "neighbor_mac": "aa:bb:cc:00:00:01"}},
			// Garbage tags are ignored (bounds-checked).
			{Kind: "vlan", RawData: map[string]string{"vlan_tag": "99999"}},
		},
	}}

	rn.recordVLANs(ctx, netID, reports)

	var n int
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vlans WHERE network_id = ?`, net.ID).Scan(&n))
	require.Equal(t, 2, n, "tags 42 (named) + 7 (traffic-only); 99999 is out of range")

	var name sql.NullString
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT name FROM vlans WHERE network_id = ? AND vlan_tag = 42`, net.ID).Scan(&name))
	require.True(t, name.Valid)
	require.Equal(t, "mgmt", name.String)

	// TWO VLANs observed → subnet stays unlinked (ambiguous broadcast domain).
	var linked sql.NullInt64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT vlan_id FROM subnets WHERE network_id = ?`, net.ID).Scan(&linked))
	require.False(t, linked.Valid, "multi-VLAN network must not auto-link its subnet")
}

// TestRecordVLANs_SingleVLANLinksSubnet: exactly one observed VLAN → the
// network's subnet gets vlan_id stamped (the by-definition association).
func TestRecordVLANs_SingleVLANLinksSubnet(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	rn := New(nil, queries, conn, nil, 0, nil)

	ctx := context.Background()
	net, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "vlan-net-1"})
	require.NoError(t, err)
	netID := sql.NullInt64{Int64: net.ID, Valid: true}

	_, err = conn.ExecContext(ctx,
		`INSERT INTO subnets (network_id, cidr, gateway) VALUES (?, '10.10.0.0/24', '10.10.0.1')`, net.ID)
	require.NoError(t, err)

	reports := []scannerv2.HostReport{{
		IP: "10.10.0.1", Alive: true,
		Evidence: []scannerv2.Evidence{
			{Kind: "vlan", RawData: map[string]string{"vlan_tag": "10", "vlan_name": "default-lan"}},
		},
	}}
	rn.recordVLANs(ctx, netID, reports)

	var vlanID sql.NullInt64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT vlan_id FROM subnets WHERE network_id = ?`, net.ID).Scan(&vlanID))
	require.True(t, vlanID.Valid, "single-VLAN network links its subnet")

	// No network scope (NULL network_id) → no-op, no error.
	rn.recordVLANs(ctx, sql.NullInt64{}, reports)

	// No VLAN evidence at all → no-op.
	rn.recordVLANs(ctx, netID, []scannerv2.HostReport{{IP: "10.10.0.2", Alive: true}})
}
