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
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// device_sightings (#527/#529): every host-resolving writer records WHERE and
// VIA WHOM a device was seen. Same tuple refreshes; changed tuple appends.

func TestRecordSighting_UpsertSemantics(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	devID := seedDeviceRow(t, repo.db, "10.0.0.10", "aa:bb:cc:dd:ee:10", sql.NullInt64{Int64: 7, Valid: true})

	ts := time.Now().UTC().Add(-2 * time.Hour)
	require.NoError(t, repo.RecordSighting(ctx, devID, "10.0.0.10", "aa:bb:cc:dd:ee:10",
		sql.NullInt64{Int64: 7, Valid: true}, "", "scan", ts))
	require.NoError(t, repo.RecordSighting(ctx, devID, "10.0.0.10", "aa:bb:cc:dd:ee:10",
		sql.NullInt64{Int64: 7, Valid: true}, "", "scan", ts.Add(time.Hour)))

	var n, cnt int
	var last time.Time
	require.NoError(t, repo.db.QueryRow(
		`SELECT COUNT(*), see_count, last_seen FROM device_sightings`).Scan(&n, &cnt, &last))
	require.EqualValues(t, 1, n, "same tuple must upsert, not append")
	require.EqualValues(t, 2, cnt)
	require.WithinDuration(t, ts.Add(time.Hour), last, time.Second)

	// A different vantage or source is a different observation stream.
	require.NoError(t, repo.RecordSighting(ctx, devID, "10.0.0.10", "aa:bb:cc:dd:ee:10",
		sql.NullInt64{Int64: 7, Valid: true}, "agent-lan-63", "agent-report", ts.Add(time.Hour)))
	require.NoError(t, repo.RecordSighting(ctx, devID, "10.0.0.11", "aa:bb:cc:dd:ee:10",
		sql.NullInt64{Int64: 7, Valid: true}, "", "passive:ebpf:arp", ts.Add(time.Hour)))
	require.NoError(t, repo.db.QueryRow(`SELECT COUNT(*) FROM device_sightings`).Scan(&n))
	require.EqualValues(t, 3, n)
}

// device_network_presence (#526): the multi-homed identity layer.
func TestUpsertNetworkPresence(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	netA, netB := int64(1), int64(2)
	seedNetworks(t, repo.db, map[int64]string{netA: "lan-a", netB: "lan-b"})
	devID := seedDeviceRow(t, repo.db, "10.0.0.1", "aa:bb:cc:dd:ee:01", sql.NullInt64{Int64: netA, Valid: true})

	require.NoError(t, repo.UpsertNetworkPresence(ctx, devID, netA, "10.0.0.1", "", time.Now().UTC()))
	require.NoError(t, repo.UpsertNetworkPresence(ctx, devID, netB, "10.0.0.2", "agent-lan-63", time.Now().UTC()))
	// Same network again: refresh ip + last_seen, still one row per network.
	require.NoError(t, repo.UpsertNetworkPresence(ctx, devID, netB, "10.0.0.9", "agent-lan-63", time.Now().UTC()))

	var rows int
	require.NoError(t, repo.db.QueryRow(`SELECT COUNT(*) FROM device_network_presence`).Scan(&rows))
	require.EqualValues(t, 2, rows)
	var ip string
	require.NoError(t, repo.db.QueryRow(
		`SELECT ip_address FROM device_network_presence WHERE network_id = ?`, netB).Scan(&ip))
	require.Equal(t, "10.0.0.9", ip, "presence ip refreshes to the network's current address")
}

// The multi-homed decision input: is the device seen FRESHLY in any network
// other than the one currently reporting? A fresh foreign presence says
// multi-homed (don't roam the row); all-stale says the device moved.
func TestHasFreshPresenceOutside(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	netA, netB := int64(1), int64(2)
	seedNetworks(t, repo.db, map[int64]string{netA: "lan-a", netB: "lan-b"})
	devID := seedDeviceRow(t, repo.db, "10.0.0.1", "aa:bb:cc:dd:ee:01", sql.NullInt64{Int64: netA, Valid: true})
	now := time.Now().UTC()

	// No presence at all: not multi-homed (first sighting / fresh DB).
	require.False(t, repo.HasFreshPresenceOutside(ctx, devID, netB, time.Hour))

	// Home presence refreshed an hour ago (older networks config: scan
	// cadences up to 6h) — freshness window 24h says still active there.
	require.NoError(t, repo.UpsertNetworkPresence(ctx, devID, netA, "10.0.0.1", "", now.Add(-time.Hour)))
	require.True(t, repo.HasFreshPresenceOutside(ctx, devID, netB, 24*time.Hour))
	// The reporting network's own presence must not count.
	require.False(t, repo.HasFreshPresenceOutside(ctx, devID, netA, 24*time.Hour))

	// Home presence stale beyond the window: the device moved away.
	require.NoError(t, repo.UpsertNetworkPresence(ctx, devID, netA, "10.0.0.1", "", now.Add(-48*time.Hour)))
	require.False(t, repo.HasFreshPresenceOutside(ctx, devID, netB, 24*time.Hour))
}

// device_neighbors carries the reporting vantage (#527).
func TestRecordNeighbors_VantageProvenance(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	seedDeviceRow(t, repo.db, "10.0.0.1", "aa:bb:cc:dd:ee:01", sql.NullInt64{})
	require.NoError(t, repo.RecordNeighbors(ctx, "10.0.0.1", "agent-lan-63", []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:10", Protocol: "LLDP"},
	}))
	require.NoError(t, repo.RecordNeighbors(ctx, "10.0.0.1", "", []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:11", Protocol: "LLDP"},
	}))

	var agent string
	require.NoError(t, repo.db.QueryRow(
		`SELECT agent_id FROM device_neighbors WHERE neighbor_mac='aa:bb:cc:dd:ee:10'`).Scan(&agent))
	require.Equal(t, "agent-lan-63", agent)
	require.NoError(t, repo.db.QueryRow(
		`SELECT agent_id FROM device_neighbors WHERE neighbor_mac='aa:bb:cc:dd:ee:11'`).Scan(&agent))
	require.Equal(t, "", agent, "center-local reports keep the empty vantage")
}

// seedNetworks inserts networks rows by id (name is UNIQUE).
func seedNetworks(t *testing.T, db *sql.DB, byID map[int64]string) {
	t.Helper()
	for id, name := range byID {
		_, err := db.Exec(`INSERT INTO networks (id, name) VALUES (?, ?)`, id, name)
		require.NoError(t, err)
	}
}
