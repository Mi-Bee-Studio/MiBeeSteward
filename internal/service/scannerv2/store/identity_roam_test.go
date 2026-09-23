// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestApplyDeviceIdentity_RoamEvictsMaclessPlaceholder pins the #399-era roam
// retry: resolve marks Roamed while the target IP is free, a racing MAC-less
// scan then inserts a mac=” placeholder at that IP, and the apply-time roam
// UPDATE hits the (ip_address, network_id) unique constraint. The eviction
// path must DELETE the placeholder and retry successfully.
func TestApplyDeviceIdentity_RoamEvictsMaclessPlaceholder(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	mac := "aa:bb:cc:dd:ee:01"
	devID := seedDeviceRow(t, conn, "10.0.0.5", mac, nid)

	res, err := repo.ResolveDeviceIdentity(ctx, mac, "10.0.0.9", nid)
	require.NoError(t, err)
	require.True(t, res.Roamed, ".9 is free at resolve time → roam")

	// Simulate the race: a MAC-less scan lands a placeholder at .9 between
	// resolve and apply.
	seedDeviceRow(t, conn, "10.0.0.9", "", nid)
	require.Equal(t, 2, countRows(t, conn, "SELECT COUNT(*) FROM devices"))

	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, Roamed: true,
		IP: "10.0.0.9", MAC: mac, NetworkID: nid,
	})
	require.NoError(t, err)

	// The placeholder was evicted and the real device relocated to .9, one
	// row total, still keyed by the original id.
	require.Equal(t, 1, countRows(t, conn, "SELECT COUNT(*) FROM devices"))
	var ip, macOut string
	require.NoError(t, conn.QueryRow(`SELECT ip_address, mac_address FROM devices WHERE id = ?`, devID).Scan(&ip, &macOut))
	require.Equal(t, "10.0.0.9", ip)
	require.Equal(t, mac, macOut)
}

// TestApplyDeviceIdentity_RoamRetryFailsOnRealHolder is the eviction path's
// guard rail: when the IP is held by a row with a REAL (non-empty) mac, the
// eviction DELETE must not remove it and the retry UPDATE fails the unique
// constraint again, the apply still returns the target id (non-fatal
// semantics) and the holder survives.
func TestApplyDeviceIdentity_RoamRetryFailsOnRealHolder(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	mac := "aa:bb:cc:dd:ee:02"
	devID := seedDeviceRow(t, conn, "10.0.0.5", mac, nid)

	res, err := repo.ResolveDeviceIdentity(ctx, mac, "10.0.0.9", nid)
	require.NoError(t, err)
	require.True(t, res.Roamed)

	// A real-mac device occupies .9 (a scenario Resolve would classify as
	// replacement, but apply must tolerate whatever write it is handed).
	holderID := seedDeviceRow(t, conn, "10.0.0.9", "11:22:33:44:55:66", nid)

	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, Roamed: true,
		IP: "10.0.0.9", MAC: mac, NetworkID: nid,
	})
	require.NoError(t, err, "roam retry failure is logged, not returned")

	// Holder untouched (DELETE keys on mac=''), roaming device stayed at .5.
	var holderIP string
	require.NoError(t, conn.QueryRow(`SELECT ip_address FROM devices WHERE id = ?`, holderID).Scan(&holderIP))
	require.Equal(t, "10.0.0.9", holderIP)
	var roamIP string
	require.NoError(t, conn.QueryRow(`SELECT ip_address FROM devices WHERE id = ?`, devID).Scan(&roamIP))
	require.Equal(t, "10.0.0.5", roamIP)
}

// TestRecordServices_MergesDuplicateServicePort drives the (service, port)
// dedup-merge: two identities sharing the key merge metadata (first-write
// wins per key, new keys added) and keep the HIGHEST confidence, so the
// UNIQUE(ip, service, port) insert never warns.
func TestRecordServices_MergesDuplicateServicePort(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	const ip = "10.0.0.7"
	err := repo.RecordServices(ctx, ip, []scannerv2.ServiceIdentity{
		{Service: "http", Port: 80, Confidence: 0.6, Metadata: map[string]string{"server": "nginx", "keep": "first"}},
		{Service: "http", Port: 80, Confidence: 0.95, Metadata: map[string]string{"server": "apache", "extra": "new"}},
		{Service: "ssh", Port: 22, Confidence: 0.9},
	}, nil)
	require.NoError(t, err)

	var httpCount int
	require.NoError(t, repo.db.QueryRow(`SELECT COUNT(*) FROM host_services WHERE ip = ? AND service = 'http'`, ip).Scan(&httpCount))
	require.Equal(t, 1, httpCount, "duplicate (service, port) collapsed to one row")

	var metadata string
	var confidence float64
	require.NoError(t, repo.db.QueryRow(
		`SELECT metadata, confidence FROM host_services WHERE ip = ? AND service = 'http'`, ip).Scan(&metadata, &confidence))
	require.Contains(t, metadata, `"server":"nginx"`, "first-write metadata value wins over the second identity's")
	require.Contains(t, metadata, `"keep":"first"`, "first identity's own keys survive the merge")
	require.Contains(t, metadata, `"extra":"new"`, "keys only the second identity had are added")
	require.InDelta(t, 0.95, confidence, 0.0001, "merged row keeps the highest confidence")
}

// TestRecordNeighbors_ResolvesViaNetworkScopedIP covers the network-scoped
// branch of resolveDeviceID (repo NetworkID valid + device on that network):
// neighbors attach to the device by (ip, network_id) without falling through
// to the global IP lookup.
func TestRecordNeighbors_ResolvesViaNetworkScopedIP(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	conn := repo.db
	_, err := conn.Exec(`INSERT INTO networks (id, name, cidr, site, created_at, updated_at)
		VALUES (1, 'n', '10.0.0.0/24', 's', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	nid := sql.NullInt64{Int64: 1, Valid: true}
	devID := seedDeviceRow(t, conn, "10.0.0.3", "aa:bb:cc:dd:ee:03", nid)

	err = repo.RecordNeighbors(ctx, "10.0.0.3", []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:99", Protocol: "LLDP", LocalPort: "eth0", RemotePort: "gi1/0/1", VLANTag: "10"},
	})
	require.NoError(t, err)

	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM device_neighbors WHERE device_id = ?`, devID).Scan(&n))
	require.Equal(t, 1, n, "neighbor attached to the network-scoped device row")
}
