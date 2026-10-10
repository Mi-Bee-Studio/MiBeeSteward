// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// RecordNeighborsByMAC is the MAC-keyed variant used by the LLDP/CDP frame
// listeners (#501): the listener knows the surveyed interface's MAC, not an
// IP, so the local end of the edge resolves by MAC instead of the IP rule
// RecordNeighbors uses.

func TestRecordNeighborsByMAC_InsertsEdges(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	localMAC := "02:11:22:33:44:55"
	seedDeviceRow(t, repo.db, "10.0.0.60", localMAC, sql.NullInt64{Int64: 7, Valid: true})

	require.NoError(t, repo.RecordNeighborsByMAC(ctx, localMAC, []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:10", Protocol: "LLDP", LocalPort: "eth0", RemotePort: "gi1/0/1"},
		{NeighborMAC: "aa:bb:cc:dd:ee:11", Protocol: "CDP"},
	}))

	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM device_neighbors`); cnt != 2 {
		t.Fatalf("expected 2 neighbor rows, got %d", cnt)
	}
	if cnt := countRows(t, repo.db,
		`SELECT COUNT(*) FROM device_neighbors WHERE local_port='eth0' AND remote_port='gi1/0/1' AND network_id=7`); cnt != 1 {
		t.Fatalf("edge should carry the local device's ports and network_id, got %d rows", cnt)
	}
}

func TestRecordNeighborsByMAC_NormalizesMAC(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	localMAC := "02:11:22:33:44:55"
	seedDeviceRow(t, repo.db, "10.0.0.61", localMAC, sql.NullInt64{})

	// The frame listener canonicalizes MACs itself, but the resolver must not
	// depend on that: uppercase input still resolves the local device.
	require.NoError(t, repo.RecordNeighborsByMAC(ctx, "02:11:22:33:44:55", []scannerv2.NeighborSpec{
		{NeighborMAC: "AA:BB:CC:DD:EE:12", Protocol: "LLDP"},
	}))
	if cnt := countRows(t, repo.db,
		`SELECT COUNT(*) FROM device_neighbors WHERE neighbor_mac='aa:bb:cc:dd:ee:12'`); cnt != 1 {
		t.Fatalf("neighbor MAC should be stored canonical, got %d rows", cnt)
	}
}

func TestRecordNeighborsByMAC_NoDeviceSkips(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	err := repo.RecordNeighborsByMAC(ctx, "02:99:99:99:99:99", []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:13", Protocol: "LLDP"},
	})
	require.NoError(t, err, "unknown local MAC is a skip, not an error")
	if cnt := countRows(t, repo.db, `SELECT COUNT(*) FROM device_neighbors`); cnt != 0 {
		t.Fatalf("expected 0 rows for unknown local MAC, got %d", cnt)
	}
}

func TestRecordNeighborsByMAC_DedupOnConflict(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	localMAC := "02:11:22:33:44:56"
	seedDeviceRow(t, repo.db, "10.0.0.62", localMAC, sql.NullInt64{})

	specs := []scannerv2.NeighborSpec{{NeighborMAC: "aa:bb:cc:dd:ee:14", Protocol: "LLDP", LocalPort: "eth0"}}
	require.NoError(t, repo.RecordNeighborsByMAC(ctx, localMAC, specs))
	// Second frame for the same adjacency: upsert, and an empty port must not
	// clobber the port recorded by the first one (same merge rule as
	// RecordNeighbors).
	specs[0].LocalPort = ""
	require.NoError(t, repo.RecordNeighborsByMAC(ctx, localMAC, specs))

	if cnt := countRows(t, repo.db,
		`SELECT COUNT(*) FROM device_neighbors WHERE neighbor_mac='aa:bb:cc:dd:ee:14'`); cnt != 1 {
		t.Fatalf("re-reported adjacency must upsert, got %d rows", cnt)
	}
	if cnt := countRows(t, repo.db,
		`SELECT COUNT(*) FROM device_neighbors WHERE neighbor_mac='aa:bb:cc:dd:ee:14' AND local_port='eth0'`); cnt != 1 {
		t.Fatal("empty-port re-report must not clobber the recorded port")
	}
}
