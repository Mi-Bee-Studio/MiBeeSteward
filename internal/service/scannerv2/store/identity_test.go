// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests exercise ResolveDeviceIdentity directly against *SQLiteRepository
// — the interface-level contract for the device-identity resolver (#159). They
// lock the MAC-primary / (ip, network_id) fallback / roam / replacement rules
// WITHOUT going through runner.applyDeviceBridge, so a future second Repository
// implementation (the distributed伏笔) can be validated against the same
// contract. The runner-level behavior is covered by the characterization tests
// in runner/device_bridge_baseline_test.go.

// resolveRepo builds a repo over a fresh in-memory DB and seeds a network row,
// returning the repo, the network's NullInt64, the underlying db (for seeding),
// and a context.
func resolveRepo(t *testing.T, networkID int64) (*SQLiteRepository, sql.NullInt64, *sql.DB, context.Context) {
	t.Helper()
	repo, ctx := newRepo(t, Options{NetworkID: networkID})
	var nid sql.NullInt64
	if networkID > 0 {
		if _, err := repo.db.Exec(`INSERT INTO networks (id, name, cidr, site, created_at, updated_at)
			VALUES (?, 'n', '10.0.0.0/24', 's', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, networkID); err != nil {
			t.Fatalf("seed network: %v", err)
		}
		nid = sql.NullInt64{Int64: networkID, Valid: true}
	}
	return repo, nid, repo.db, ctx
}

func TestResolveDeviceIdentity_NoMAC_NewRow(t *testing.T) {
	repo, nid, _, ctx := resolveRepo(t, 1)
	res, err := repo.ResolveDeviceIdentity(ctx, "", "10.0.0.5", nid)
	require.NoError(t, err)
	require.True(t, res.IsNew, "no MAC and no existing (ip,network) row → IsNew")
	require.Zero(t, res.TargetID)
}

func TestResolveDeviceIdentity_NoMAC_MatchesByIPNetwork(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	id := seedDeviceRow(t, db, "10.0.0.5", "", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "", "10.0.0.5", nid)
	require.NoError(t, err)
	require.False(t, res.IsNew)
	require.Equal(t, id, res.TargetID, "no MAC → identity is (ip, network_id)")
	require.Zero(t, res.ReplacedID)
	require.False(t, res.Roamed)
}

func TestResolveDeviceIdentity_MACMatch_SameIP_NormalUpdate(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	id := seedDeviceRow(t, db, "10.0.0.5", "aa:bb:cc:dd:ee:01", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:01", "10.0.0.5", nid)
	require.NoError(t, err)
	require.Equal(t, id, res.TargetID)
	require.False(t, res.Roamed, "same IP → normal update, not a roam")
	require.Zero(t, res.ReplacedID)
}

func TestResolveDeviceIdentity_MACMatch_NewFreeIP_IsRoam(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	// Device known at .5 by MAC; scans now see it at .9 (free IP) → DHCP roam.
	id := seedDeviceRow(t, db, "10.0.0.5", "aa:bb:cc:dd:ee:01", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:01", "10.0.0.9", nid)
	require.NoError(t, err)
	require.Equal(t, id, res.TargetID)
	require.True(t, res.Roamed, "MAC matched a device whose old IP is now free → roam")
	require.Zero(t, res.ReplacedID)
}

func TestResolveDeviceIdentity_MACMatch_DifferentMACHoldsIP_IsReplacement(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	// Prior asset known by MAC-A at .100 (a stale/transient IP).
	priorID := seedDeviceRow(t, db, "10.0.0.100", "aa:bb:cc:dd:ee:01", nid)
	// A different device (MAC-B) now occupies the scanned IP .5.
	holderID := seedDeviceRow(t, db, "10.0.0.5", "bb:bb:bb:bb:bb:02", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:01", "10.0.0.5", nid)
	require.NoError(t, err)
	require.Equal(t, holderID, res.TargetID, "the IP-holder becomes the update target")
	require.Equal(t, priorID, res.ReplacedID, "the prior MAC-matched row is superseded")
	require.False(t, res.Roamed)
}

func TestResolveDeviceIdentity_MACMatch_EmptyMACHolder_NotReplacement(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	// Device known by MAC-A at .100 (a different IP than the scan target).
	id := seedDeviceRow(t, db, "10.0.0.100", "aa:bb:cc:dd:ee:01", nid)
	// The scanned IP .5 is held by a MAC-less placeholder (a stale mac-less
	// discovery). This is NOT a replacement — the placeholder should be filled,
	// not treated as a conflict.
	seedDeviceRow(t, db, "10.0.0.5", "", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:01", "10.0.0.5", nid)
	require.NoError(t, err)
	require.Equal(t, id, res.TargetID, "MAC match wins; empty-mac holder is not a replacement")
	require.Zero(t, res.ReplacedID)
}

func TestResolveDeviceIdentity_MACUnseen_FallsBackToIPEmptyMAC(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	// A MAC-less placeholder exists at .5; a later scan with a fresh MAC for .5
	// must match the placeholder (so its mac gets filled), not be flagged IsNew.
	id := seedDeviceRow(t, db, "10.0.0.5", "", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:09", "10.0.0.5", nid)
	require.NoError(t, err)
	require.False(t, res.IsNew)
	require.Equal(t, id, res.TargetID, "unseen MAC falls back to (ip, network_id, mac='')")
}

func TestResolveDeviceIdentity_NullNetwork_Branches(t *testing.T) {
	// Legacy single-instance path: networkID invalid → the network_id IS NULL
	// branches. A device with NULL network_id must resolve; a device on a
	// non-zero network must NOT match (cross-network isolation).
	repo, _, db, ctx := resolveRepo(t, 0) // NetworkID 0 → NULL network
	nullNID := sql.NullInt64{}
	id := seedDeviceRow(t, db, "172.16.0.5", "aa:bb:cc:dd:ee:0a", nullNID)
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:0a", "172.16.0.5", nullNID)
	require.NoError(t, err)
	require.Equal(t, id, res.TargetID, "NULL-network device resolves on the legacy path")

	// A device on network 1 must NOT match a NULL-network resolve (isolation).
	seedDeviceRow(t, db, "172.16.0.5", "cc:cc:cc:cc:cc:0c", sql.NullInt64{Int64: 1, Valid: true})
	res, err = repo.ResolveDeviceIdentity(ctx, "", "172.16.0.5", nullNID)
	require.NoError(t, err)
	require.Equal(t, id, res.TargetID, "NULL-network resolve matches only NULL-network rows")
}
