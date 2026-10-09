// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package store

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// randomizedMAC / realMAC: locally-administered (randomized client) vs a
// globally-administered (real vendor) MAC. 2a:… mirrors the lan-62 incident
// (a privacy-MAC phone serially force-replacing idle IoT rows).
const (
	randomizedMAC = "2a:6c:07:aa:bb:cc"
	realMAC       = "b8:27:eb:d4:7e:da"
)

// TestResolve_RandomizedMAC_NeverTakesOverRealHolder: the core guard. A
// randomized MAC reporting at an IP held by a REAL-mac device must resolve
// to IsNew + ParkHolderID (holder parked, fresh row created) — NOT TakeOver
// (which would force-overwrite the holder's identity).
func TestResolve_RandomizedMAC_NeverTakesOverRealHolder(t *testing.T) {
	repo, nid, _, ctx := resolveRepo(t, 1)
	holder := seedDeviceRow(t, repo.db, "10.0.0.5", realMAC, nid)

	res, err := repo.ResolveDeviceIdentity(ctx, randomizedMAC, "10.0.0.5", nid)
	require.NoError(t, err)
	require.True(t, res.IsNew, "randomized MAC → new row, never a take-over")
	require.Equal(t, holder, res.ParkHolderID, "holder must be parked to free the slot")
	require.False(t, res.TakeOver)
	require.Zero(t, res.TargetID)
}

// TestResolve_VendorMAC_StillTakesOver: the classic swapped-board doctrine
// is UNCHANGED for real MACs — contrast case for the guard above.
func TestResolve_VendorMAC_StillTakesOver(t *testing.T) {
	repo, nid, _, ctx := resolveRepo(t, 1)
	holder := seedDeviceRow(t, repo.db, "10.0.0.5", realMAC, nid)

	res, err := repo.ResolveDeviceIdentity(ctx, "d8:3a:dd:11:22:33", "10.0.0.5", nid)
	require.NoError(t, err)
	require.False(t, res.IsNew)
	require.True(t, res.TakeOver, "a real vendor MAC still force-takes the occupied slot")
	require.Equal(t, holder, res.TargetID)
	require.Zero(t, res.ParkHolderID)
}

// TestResolve_RandomizedMAC_CanTakeVacantSlots: the guard only protects
// REAL-mac holders. An empty-mac (or randomized-mac) placeholder may still
// be taken over by a randomized MAC — filling a vacuum destroys nothing.
func TestResolve_RandomizedMAC_CanTakeVacantSlots(t *testing.T) {
	repo, nid, _, ctx := resolveRepo(t, 1)

	t.Run("empty-mac holder", func(t *testing.T) {
		// A MAC-less slot is filled by the MAC (plain update path, the
		// (ip, network, mac='') fallback) — no take-over needed, and a
		// randomized MAC filling a vacuum is fine.
		holder := seedDeviceRow(t, repo.db, "10.0.0.5", "", nid)
		res, err := repo.ResolveDeviceIdentity(ctx, randomizedMAC, "10.0.0.5", nid)
		require.NoError(t, err)
		require.False(t, res.TakeOver)
		require.Equal(t, holder, res.TargetID, "empty-mac slot is filled in place")
		require.Zero(t, res.ParkHolderID)
	})

	t.Run("randomized-mac holder", func(t *testing.T) {
		holder := seedDeviceRow(t, repo.db, "10.0.0.6", "aa:bb:cc:00:00:01", nid) // 0xAA local
		res, err := repo.ResolveDeviceIdentity(ctx, randomizedMAC, "10.0.0.6", nid)
		require.NoError(t, err)
		require.True(t, res.TakeOver)
		require.Equal(t, holder, res.TargetID)
	})
}

// TestResolve_RandomizedMAC_NeverReplaces: the replacement branch. A
// randomized MAC with its OWN row (seen at another IP) that lands on a slot
// held by a real device must ROAM its own row (with the holder parked), not
// replace the holder — and must NOT mark its own row superseded.
func TestResolve_RandomizedMAC_NeverReplaces(t *testing.T) {
	repo, nid, _, ctx := resolveRepo(t, 1)
	phoneRow := seedDeviceRow(t, repo.db, "10.0.0.5", randomizedMAC, nid)
	holder := seedDeviceRow(t, repo.db, "10.0.0.9", realMAC, nid)

	res, err := repo.ResolveDeviceIdentity(ctx, randomizedMAC, "10.0.0.9", nid)
	require.NoError(t, err)
	require.False(t, res.ReplacedID != 0, "no row may be superseded by a randomized MAC")
	require.Equal(t, phoneRow, res.TargetID, "the scanned device's own row is the target")
	require.True(t, res.Roamed, "its row roams onto the freed IP")
	require.Equal(t, holder, res.ParkHolderID)
}

// TestApply_ParkHolder_EndToEnd: resolve + apply through the whole path —
// holder parked (ip cleared, identity intact), new row created for the
// randomized client, and the (ip, network) unique index satisfied.
func TestApply_ParkHolder_EndToEnd(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	holder := seedDeviceRow(t, conn, "10.0.0.5", realMAC, nid)
	setDeviceIdentity(t, conn, holder, "waterheater-demo", "embedded", "vendor-demo")

	res, err := repo.ResolveDeviceIdentity(ctx, randomizedMAC, "10.0.0.5", nid)
	require.NoError(t, err)

	newID, err := repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		IsNew: true, ParkHolderID: res.ParkHolderID,
		IP: "10.0.0.5", MAC: randomizedMAC, NetworkID: nid,
		Name: "t1-pro", Type: "phone", ScanAttributesJSON: "{}",
	})
	require.NoError(t, err)
	require.NotZero(t, newID)
	require.NotEqual(t, holder, newID)

	// holder: parked, identity columns untouched, still online-able by MAC
	var hIP, hName, hBrand string
	require.NoError(t, conn.QueryRow(
		`SELECT ip_address, name, brand FROM devices WHERE id = ?`, holder).
		Scan(&hIP, &hName, &hBrand))
	require.Equal(t, fmt.Sprintf("#park:%d", holder), hIP, "holder parked off the IP")
	require.Equal(t, "waterheater-demo", hName)
	require.Equal(t, "vendor-demo", hBrand)

	// new row owns the slot
	var nMAC string
	require.NoError(t, conn.QueryRow(
		`SELECT mac_address FROM devices WHERE ip_address = '10.0.0.5' AND network_id = 1`).Scan(&nMAC))
	require.Equal(t, randomizedMAC, nMAC)

	// the holder re-resolves by MAC and can roam anywhere later
	res2, err := repo.ResolveDeviceIdentity(ctx, realMAC, "10.0.0.12", nid)
	require.NoError(t, err)
	require.Equal(t, holder, res2.TargetID)
	require.True(t, res2.Roamed, "real device returning at a free IP roams onto it")
}

// TestResolve_DuplicateMACRows_PreferLiveAndFresh: when duplicate rows share
// a MAC (legacy churn artifacts), the lookup is deterministic — online first,
// then freshest — instead of rowid order.
func TestResolve_DuplicateMACRows_PreferLiveAndFresh(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	stale := seedDeviceRow(t, conn, "10.0.0.5", randomizedMAC, nid)
	live := seedDeviceRow(t, conn, "10.0.0.6", randomizedMAC, nid)

	// stale row: offline for a long time; live row: seen recently
	_, err := conn.Exec(`UPDATE devices SET status='offline', offline_since='2026-01-01T00:00:00Z', last_seen='2026-01-01T00:00:00Z' WHERE id = ?`, stale)
	require.NoError(t, err)
	_, err = conn.Exec(`UPDATE devices SET status='online', last_seen='2026-10-06T00:00:00Z' WHERE id = ?`, live)
	require.NoError(t, err)

	res, err := repo.ResolveDeviceIdentity(ctx, randomizedMAC, "10.0.0.7", nid)
	require.NoError(t, err)
	require.Equal(t, live, res.TargetID, "the live row wins, not rowid order")
}

// setDeviceIdentity stamps name/type/brand on a seeded row (test helper).
func setDeviceIdentity(t *testing.T, db *sql.DB, id int64, name, typ, brand string) {
	t.Helper()
	_, err := db.Exec(`UPDATE devices SET name = ?, type = ?, brand = ? WHERE id = ?`, name, typ, brand, id)
	require.NoError(t, err)
}

// TestApply_ParkHolder_MultipleHoldersSameNetwork pins the 2026-10-10 field
// failure: parking clears the holder's IP to '' — but the unique
// (ip_address, network_id) index allows only ONE empty-IP row per network,
// so the second+ park on the same network trips the constraint, the park
// fails, and the subsequent create at the contested IP fails too — every
// scan cycle (four holders logged ~340 WARNs/day). Parking must give each
// holder a unique non-IP sentinel so any number of holders can be parked.
func TestApply_ParkHolder_MultipleHoldersSameNetwork(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	holderA := seedDeviceRow(t, conn, "10.0.0.5", realMAC, nid)
	holderB := seedDeviceRow(t, conn, "10.0.0.6", "e4:aa:ec:11:22:33", nid)

	apply := func(parkID int64, mac, ip string) int64 {
		res, err := repo.ResolveDeviceIdentity(ctx, mac, ip, nid)
		require.NoError(t, err)
		newID, err := repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
			IsNew: true, ParkHolderID: res.ParkHolderID,
			IP: ip, MAC: mac, NetworkID: nid,
			Name: "rand-" + ip, Type: "phone", ScanAttributesJSON: "{}",
		})
		require.NoError(t, err, "create after parking %d must succeed", parkID)
		return newID
	}

	apply(holderA, randomizedMAC, "10.0.0.5")
	apply(holderB, "2a:6c:07:dd:ee:ff", "10.0.0.6")

	var parkedA, parkedB string
	require.NoError(t, conn.QueryRow(`SELECT ip_address FROM devices WHERE id = ?`, holderA).Scan(&parkedA))
	require.NoError(t, conn.QueryRow(`SELECT ip_address FROM devices WHERE id = ?`, holderB).Scan(&parkedB))
	require.NotEqual(t, "10.0.0.5", parkedA, "holder A off its IP")
	require.NotEqual(t, "10.0.0.6", parkedB, "holder B off its IP")
	require.NotEqual(t, parkedA, parkedB, "two parked holders must not collide on the same sentinel")
	require.NotEqual(t, "", parkedA, "parked sentinel must be a distinguishable value, not the unique-indexed ''")
	require.NotEqual(t, "", parkedB, "parked sentinel must be a distinguishable value, not the unique-indexed ''")

	// Both randomized rows own their slots now.
	var n int
	require.NoError(t, conn.QueryRow(
		`SELECT COUNT(*) FROM devices WHERE ip_address IN ('10.0.0.5','10.0.0.6') AND network_id = 1`).Scan(&n))
	require.Equal(t, 2, n)
}
