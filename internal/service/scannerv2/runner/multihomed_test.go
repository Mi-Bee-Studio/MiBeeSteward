// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
)

// The multi-homed identity layer (#526): a dual-homed router reported by two
// agents (one per network) must stay ONE device row — home network untouched,
// the foreign presence recorded — instead of ping-ponging its ip/network at
// scan cadence. A genuine mover (home presence stale) relocates the row AND
// its network. Every bridge apply records a sighting (#527).

func setupTwoNetworks(t *testing.T) (*Runner, int64, int64, *sql.DB) {
	t.Helper()
	rn, queries, conn := setupChangeDetectDB(t)
	home := rn.networkID.Int64
	foreign, err := queries.CreateNetwork(context.Background(), db.CreateNetworkParams{Name: "lan-foreign"})
	require.NoError(t, err)
	return rn, home, foreign.ID, conn
}

func TestApplyDeviceBridge_MultiHomedNoPingPong(t *testing.T) {
	rn, home, foreign, conn := setupTwoNetworks(t)
	ctx := context.Background()
	mac := "aa:bb:cc:dd:ee:61"
	routerIP := "192.168.1.61" // home network CIDR
	foreignIP := "192.168.2.61"

	// The router is first scanned by the home agent.
	_, _ = rn.applyDeviceBridge(ctx, reportFor(routerIP, "router", "", mac), rn.networkID, "agent-home")
	var devID int64
	require.NoError(t, conn.QueryRow(`SELECT id FROM devices WHERE mac_address = ?`, mac).Scan(&devID))

	// The foreign agent reports the same asset at ITS address, alternating
	// with home reports — exactly the production dual-homed cadence.
	for i := 0; i < 3; i++ {
		_, _ = rn.applyDeviceBridge(ctx, reportFor(foreignIP, "router", "", mac),
			sql.NullInt64{Int64: foreign, Valid: true}, "agent-foreign")
		_, _ = rn.applyDeviceBridge(ctx, reportFor(routerIP, "router", "", mac), rn.networkID, "agent-home")
	}

	var ip string
	var netID int64
	require.NoError(t, conn.QueryRow(
		`SELECT ip_address, network_id FROM devices WHERE id = ?`, devID).Scan(&ip, &netID))
	require.Equal(t, routerIP, ip, "the row keeps its home-network address")
	require.Equal(t, home, netID, "the row keeps its home network")

	// The presence layer records BOTH networks: the graph's interconnect fact.
	var presences int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM device_network_presence WHERE device_id = ?`, devID).Scan(&presences))
	require.EqualValues(t, 2, presences)
	var fip string
	require.NoError(t, conn.QueryRow(
		`SELECT ip_address FROM device_network_presence WHERE device_id = ? AND network_id = ?`,
		devID, foreign).Scan(&fip))
	require.Equal(t, foreignIP, fip)

	// One row only — no per-network ghost.
	var rows int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ?`, mac).Scan(&rows))
	require.EqualValues(t, 1, rows)
}

func TestApplyDeviceBridge_MovedDeviceRelocatesNetwork(t *testing.T) {
	rn, _, foreign, conn := setupTwoNetworks(t)
	ctx := context.Background()
	mac := "aa:bb:cc:dd:ee:62"

	// Device lived in the home network once — long ago (stale presence).
	_, _ = rn.applyDeviceBridge(ctx, reportFor("192.168.1.62", "pc", "", mac), rn.networkID, "agent-home")
	var devID int64
	require.NoError(t, conn.QueryRow(`SELECT id FROM devices WHERE mac_address = ?`, mac).Scan(&devID))
	require.NoError(t, rn.repo.UpsertNetworkPresence(ctx, devID, rn.networkID.Int64, "192.168.1.62",
		"agent-home", time.Now().UTC().Add(-48*time.Hour)))

	// It now answers in the foreign network and nowhere else: the row must
	// RELOCATE — ip AND network_id (the pre-#526 roam left network_id behind,
	// feeding the reconcile drift counter forever).
	_, _ = rn.applyDeviceBridge(ctx, reportFor("192.168.2.62", "pc", "", mac),
		sql.NullInt64{Int64: foreign, Valid: true}, "agent-foreign")

	var ip string
	var netID int64
	require.NoError(t, conn.QueryRow(
		`SELECT ip_address, network_id FROM devices WHERE id = ?`, devID).Scan(&ip, &netID))
	require.Equal(t, "192.168.2.62", ip)
	require.Equal(t, foreign, netID, "a genuine move carries the network with the row")
}

// Every bridge apply records a sighting (#527): where, via which vantage,
// from which pipeline stage. Same tuple upserts; a new address appends.
func TestApplyDeviceBridge_RecordsSightings(t *testing.T) {
	rn, _, _, conn := setupTwoNetworks(t)
	ctx := context.Background()
	mac := "aa:bb:cc:dd:ee:63"

	_, _ = rn.applyDeviceBridge(ctx, reportFor("192.168.1.63", "pc", "", mac), rn.networkID, "")
	var devID int64
	require.NoError(t, conn.QueryRow(`SELECT id FROM devices WHERE mac_address = ?`, mac).Scan(&devID))
	_, _ = rn.applyDeviceBridge(ctx, reportFor("192.168.1.63", "pc", "", mac), rn.networkID, "")

	var sightings int
	var vantages int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM device_sightings WHERE device_id = ? AND ip_address = '192.168.1.63'`,
		devID).Scan(&sightings))
	require.EqualValues(t, 1, sightings, "same tuple upserts, see_count grows instead")
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(DISTINCT vantage) FROM device_sightings WHERE device_id = ?`, devID).Scan(&vantages))
	require.EqualValues(t, 1, vantages)

	// A DHCP roam within the same network appends a new tuple.
	_, _ = rn.applyDeviceBridge(ctx, reportFor("192.168.1.164", "pc", "", mac), rn.networkID, "")
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM device_sightings WHERE device_id = ?`, devID).Scan(&sightings))
	require.EqualValues(t, 2, sightings)
}
