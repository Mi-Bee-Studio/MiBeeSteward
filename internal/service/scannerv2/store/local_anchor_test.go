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

// AnchorLocalInterfaces (#522): the scan center knows its own interfaces'
// MACs — the one fact ARP self-scan can never learn (loopback shortcut, no
// wire frame). Filling the center's own device row mac_address is the local
// anchor every MAC-keyed neighbor source (LLDP/CDP frames, hostapd edges)
// resolves against; without it RecordNeighborsByMAC silently drops every row.

func TestAnchorLocalInterfaces_FillsEmptyMAC(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	net := sql.NullInt64{Int64: 7, Valid: true}
	// The center's own row, created by self-scan: MAC empty (the field-found
	// #522 gap). A second ordinary row shares the network.
	centerID := seedDeviceRow(t, repo.db, "10.0.0.1", "", net)
	seedDeviceRow(t, repo.db, "10.0.0.2", "aa:bb:cc:dd:ee:02", net)

	anchored, err := repo.AnchorLocalInterfaces(ctx, net, []scannerv2.IPMACPair{
		{IP: "10.0.0.1", MAC: "02:11:22:33:44:01"},
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, anchored)

	var mac string
	require.NoError(t, repo.db.QueryRow(`SELECT mac_address FROM devices WHERE id = ?`, centerID).Scan(&mac))
	require.Equal(t, "02:11:22:33:44:01", mac, "the center's own row must gain its interface MAC")
}

func TestAnchorLocalInterfaces_NeverOverwrites(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	net := sql.NullInt64{Int64: 7, Valid: true}
	// A learned MAC on the row is trusted; the anchor only fills the empty
	// case (a different existing MAC is a different investigation, not the
	// anchor's call).
	seedDeviceRow(t, repo.db, "10.0.0.1", "aa:bb:cc:dd:ee:0f", net)

	anchored, err := repo.AnchorLocalInterfaces(ctx, net, []scannerv2.IPMACPair{
		{IP: "10.0.0.1", MAC: "02:11:22:33:44:01"},
	})
	require.NoError(t, err)
	require.Zero(t, anchored)

	var mac string
	require.NoError(t, repo.db.QueryRow(`SELECT mac_address FROM devices WHERE ip_address = '10.0.0.1'`).Scan(&mac))
	require.Equal(t, "aa:bb:cc:dd:ee:0f", mac)
}

func TestAnchorLocalInterfaces_NetworkScoped(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	localNet := sql.NullInt64{Int64: 7, Valid: true}
	// Same IP string in a DIFFERENT network (multi-site overlap): the anchor
	// must not leak the center's MAC into a foreign network's row.
	foreignID := seedDeviceRow(t, repo.db, "10.0.0.1", "", sql.NullInt64{Int64: 9, Valid: true})

	anchored, err := repo.AnchorLocalInterfaces(ctx, localNet, []scannerv2.IPMACPair{
		{IP: "10.0.0.1", MAC: "02:11:22:33:44:01"},
	})
	require.NoError(t, err)
	require.Zero(t, anchored)

	var mac string
	require.NoError(t, repo.db.QueryRow(`SELECT mac_address FROM devices WHERE id = ?`, foreignID).Scan(&mac))
	require.Empty(t, mac)
}

// The #522 acceptance story end-to-end at store level: anchor the center's
// row, then the LLDP frame listener's MAC-keyed persist finds its local
// anchor and neighbor rows land instead of being silently dropped.
func TestAnchorLocalInterfaces_NeighborsLandAfterAnchor(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	net := sql.NullInt64{Int64: 7, Valid: true}
	centerMAC := "02:11:22:33:44:01"
	seedDeviceRow(t, repo.db, "10.0.0.1", "", net)

	specs := []scannerv2.NeighborSpec{{NeighborMAC: "aa:bb:cc:dd:ee:10", Protocol: "LLDP", LocalPort: "eth0"}}
	require.NoError(t, repo.RecordNeighborsByMAC(ctx, centerMAC, specs))
	require.Zero(t, countRows(t, repo.db, `SELECT COUNT(*) FROM device_neighbors`),
		"before the anchor the local MAC resolves to nothing and rows drop")

	_, err := repo.AnchorLocalInterfaces(ctx, net, []scannerv2.IPMACPair{{IP: "10.0.0.1", MAC: centerMAC}})
	require.NoError(t, err)

	require.NoError(t, repo.RecordNeighborsByMAC(ctx, centerMAC, specs))
	require.EqualValues(t, 1, countRows(t, repo.db, `SELECT COUNT(*) FROM device_neighbors`),
		"after the anchor the same frame persists")
}

// ResolveDeviceIdentity guards for MAC-keyed sightings (#522): a report that
// carries no L3 location ('' from the listeners, or an '#anchor:' sentinel
// from the chassis synthesizer) must never drive the (ip, network_id)
// fallback, the holder take-over, or a roam decision — an absent IP is "no
// information", not "moved to nothing".

func TestResolveDeviceIdentity_NoLocationNeverConflatesRows(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	net := sql.NullInt64{Int64: 7, Valid: true}
	// Two chassis-anchored rows (different MACs, anchor sentinels) coexist in
	// one network — the unique (ip, network_id) index tolerates them because
	// the sentinels are unique by construction.
	chassisA := seedDeviceRow(t, repo.db, scannerv2.AnchorIP("aa:bb:cc:dd:ee:10"), "aa:bb:cc:dd:ee:10", net)
	seedDeviceRow(t, repo.db, scannerv2.AnchorIP("aa:bb:cc:dd:ee:11"), "aa:bb:cc:dd:ee:11", net)

	// Second sighting of chassis A with no IP: must resolve to A's own row,
	// never take over B's (the empty/anchor-ip holder lookup is skipped).
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:10", "", net)
	require.NoError(t, err)
	require.Equal(t, chassisA, res.TargetID)
	require.False(t, res.TakeOver || res.ReplacedID != 0, "no-location reports never trigger take-over")
}

func TestResolveDeviceIdentity_NoLocationNeverRoams(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	net := sql.NullInt64{Int64: 7, Valid: true}
	mac := "aa:bb:cc:dd:ee:20"
	// The device is known WITH a real IP; a later chassis-only sighting (no
	// IP) must not read as "roamed to empty" and blank the row's IP.
	seedDeviceRow(t, repo.db, "10.0.0.20", mac, net)

	for _, ip := range []string{"", scannerv2.AnchorIP(mac)} {
		res, err := repo.ResolveDeviceIdentity(ctx, mac, ip, net)
		require.NoError(t, err)
		require.False(t, res.Roamed, "ip %q must not be a roam target", ip)
	}
}

func TestResolveDeviceIdentity_NoLocationUnknownMACIsNew(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	net := sql.NullInt64{Int64: 7, Valid: true}
	// An unrelated empty-IP placeholder exists; a no-location sighting of a
	// never-seen MAC must still be IsNew (the placeholder is not its slot).
	seedDeviceRow(t, repo.db, "", "aa:bb:cc:dd:ee:30", net)

	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:99", "", net)
	require.NoError(t, err)
	require.True(t, res.IsNew)
}
