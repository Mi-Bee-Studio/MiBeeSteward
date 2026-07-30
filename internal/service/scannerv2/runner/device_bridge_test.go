// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
)

// deviceRow holds the columns asserted on by the identity tests below.
type deviceRow struct {
	ID     int64
	IP     string
	MAC    string
	Status string
	Brand  string
	Name   string // devices.name (display)
}

func fetchDevice(t *testing.T, conn *sql.DB, id int64) deviceRow {
	t.Helper()
	var r deviceRow
	err := conn.QueryRow(
		`SELECT id, ip_address, mac_address, status, brand, name FROM devices WHERE id = ?`, id).
		Scan(&r.ID, &r.IP, &r.MAC, &r.Status, &r.Brand, &r.Name)
	require.NoError(t, err)
	return r
}

func countDevices(t *testing.T, conn *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n))
	return n
}

// TestApplyDeviceBridge_DeviceReplacement reproduces the router-swap split bug:
// the new router's MAC was first seen on a transient DHCP ip (.100), and it then
// took over the gateway ip (.1) still occupied by the prior router. The scan of
// (.1, newMAC) must update the .1 row (the ip-holder, now the authority for that
// location) and mark the .100 row offline — NOT write the new data onto the stale
// .100 row while leaving .1 showing the dead old router. Because this is a NEW
// physical device, its name/type/brand must FULLY replace the prior device's
// (the old identity is preserved in the device_changed change_log event, not in
// the device row).
func TestApplyDeviceBridge_DeviceReplacement(t *testing.T) {
	rn, queries, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// Prior router occupying the gateway ip .1 with its own mac + identity.
	prior := reportFor("192.168.63.1", "router", "iStoreOS", "6a:27:19:ac:fb:91")
	prior.Device.Fields["sys_name"] = "NanoPiR4S" // drives devices.name via deviceDisplayName
	_, _ = rn.applyDeviceBridge(ctx, prior, rn.networkID, "")
	// New router first seen on a transient DHCP ip .100 with its own (new) mac.
	newDev := reportFor("192.168.63.100", "embedded", "GL.iNet", "94:83:c4:29:97:3e")
	newDev.Device.Fields["sys_name"] = "GL-MT3000"
	_, _ = rn.applyDeviceBridge(ctx, newDev, rn.networkID, "")

	// Snapshot the two created rows so we can track them after the swap.
	var gatewayID, staleID int64
	require.NoError(t, conn.QueryRow(
		`SELECT id FROM devices WHERE ip_address='192.168.63.1' AND network_id=?`, rn.networkID.Int64).Scan(&gatewayID))
	require.NoError(t, conn.QueryRow(
		`SELECT id FROM devices WHERE ip_address='192.168.63.100' AND network_id=?`, rn.networkID.Int64).Scan(&staleID))
	require.NotEqual(t, gatewayID, staleID, "two distinct rows before swap")
	// Confirm the prior identity is recorded BEFORE the swap.
	require.Equal(t, "NanoPiR4S", fetchDevice(t, conn, gatewayID).Name, "gateway row starts as NanoPiR4S")
	require.Equal(t, "iStoreOS", fetchDevice(t, conn, gatewayID).Brand, "gateway brand starts as iStoreOS")
	beforeCount := countDevices(t, conn)
	require.Equal(t, 2, beforeCount)

	// The new router takes over .1: scan sees (.1, newMAC). The MAC matches the
	// stale .100 row, but .1 is held by a different-MAC device → replacement.
	swap := reportFor("192.168.63.1", "embedded", "GL.iNet", "94:83:c4:29:97:3e")
	swap.Device.Fields["sys_name"] = "GL-MT3000"
	_, _ = rn.applyDeviceBridge(ctx, swap, rn.networkID, "")

	// No new row created: the swap updates two existing rows, not insert.
	require.Equal(t, beforeCount, countDevices(t, conn), "no new device row from swap")

	gw := fetchDevice(t, conn, gatewayID)
	stale := fetchDevice(t, conn, staleID)

	// Identity fields fully replaced — the device row reflects the NEW device.
	require.Equal(t, "GL-MT3000", gw.Name, "name replaced: NanoPiR4S → GL-MT3000")
	require.Equal(t, "GL.iNet", gw.Brand, "brand replaced: iStoreOS → GL.iNet")
	require.Equal(t, "94:83:c4:29:97:3e", gw.MAC, "mac overwritten with new device mac")
	require.Equal(t, "online", gw.Status, "gateway row online (the scanned host is alive)")
	// scan_attributes carries the new device's data via json_patch.
	var scanAttrs string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE id=?`, gatewayID).Scan(&scanAttrs))
	require.Contains(t, scanAttrs, "GL-MT3000", "new hostname landed in scan_attributes")
	require.Contains(t, scanAttrs, "GL.iNet", "new brand landed in scan_attributes")

	// The stale .100 row (the new router's old DHCP sighting) is superseded.
	require.Equal(t, "offline", stale.Status, "prior mac-matched row marked offline")

	// The OLD identity (NanoPiR4S / iStoreOS) must be recorded in change_log as a
	// device_changed event — that is where the historical "what it was before"
	// lives, so the device row itself always shows the current truth.
	events, err := queries.ListChangeLog(ctx, dbListAllParams())
	require.NoError(t, err)
	var changed bool
	for _, e := range events {
		if e.ChangeType == "device_changed" && e.EntityID != nil && *e.EntityID == gatewayID {
			changed = true
		}
	}
	require.True(t, changed, "a device_changed event records the prior identity for the gateway row")
}

// dbListAllParams returns ListChangeLog params that match all rows (no filters).
func dbListAllParams() db.ListChangeLogParams {
	return db.ListChangeLogParams{
		Column1: 0, NetworkID: nil,
		Column3: "", ChangeType: "",
		Column5: "", EntityType: "",
		Limit: 100, Offset: 0,
	}
}

// TestApplyDeviceBridge_RoamingNotReplacement is the regression guard for the
// legitimate roaming case: a device seen at .10 with mac M, then re-scanned at
// .20 with the SAME mac M, where .20 is FREE (no different-mac holder). This must
// stay a single-asset update — NOT a replacement — preserving the MAC-primary
// roaming semantics (TestRecordDevice_MACPrimaryDedup).
func TestApplyDeviceBridge_RoamingNotReplacement(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// Device first seen at .10.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("192.168.63.10", "camera", "hikvision", "aa:bb:cc:dd:ee:10"), rn.networkID, "")
	var roamingID int64
	require.NoError(t, conn.QueryRow(
		`SELECT id FROM devices WHERE mac_address='aa:bb:cc:dd:ee:10'`).Scan(&roamingID))
	beforeCount := countDevices(t, conn)
	require.Equal(t, 1, beforeCount)

	// Same mac, now answering from a different (free) ip .20 — pure roaming.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("192.168.63.20", "camera", "hikvision", "aa:bb:cc:dd:ee:10"), rn.networkID, "")

	// Still exactly one row: MAC matched globally, no new row, no replacement.
	require.Equal(t, beforeCount, countDevices(t, conn), "roaming must not create or split rows")
	after := fetchDevice(t, conn, roamingID)
	require.Equal(t, "aa:bb:cc:dd:ee:10", after.MAC)
	require.Equal(t, "online", after.Status, "roaming device stays online")
	// The device ROAMED to a new IP — the registry must reflect the CURRENT IP,
	// not the first-seen one. (Prior behavior kept the stale IP; that left a NAS
	// that renewed its DHCP lease showing an address days out of date.)
	require.Equal(t, "192.168.63.20", after.IP, "roaming relocates ip_address to the scanned ip")
}

// TestApplyDeviceBridge_MACFirstResolveNotReplacement guards the "MAC fills on
// rescan" path: a device first seen WITHOUT a mac (matched by ip+network), then
// a later scan resolves the mac. This must fill the existing row's mac — NOT be
// mistaken for a replacement conflict (the ip-holder's mac is empty, which is the
// distinguishing condition). Mirrors TestRecordDevice_MACFillsOnRescan.
func TestApplyDeviceBridge_MACFirstResolveNotReplacement(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// First scan: no MAC. A DeviceRef with an empty mac field.
	noMacReport := reportFor("192.168.63.20", "embedded", "", "")
	noMacReport.Device.Fields["mac"] = "" // ensure no mac leak
	_, _ = rn.applyDeviceBridge(ctx, noMacReport, rn.networkID, "")

	var holderID int64
	require.NoError(t, conn.QueryRow(
		`SELECT id FROM devices WHERE ip_address='192.168.63.20' AND network_id=?`, rn.networkID.Int64).Scan(&holderID))
	holder := fetchDevice(t, conn, holderID)
	require.Equal(t, "", holder.MAC, "first scan leaves mac empty")

	// Second scan resolves the mac. The mac is NOT on any other device, and the
	// ip-holder's mac is empty → must fill, not trigger replacement.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("192.168.63.20", "embedded", "raspberry", "aa:bb:cc:dd:ee:20"), rn.networkID, "")

	require.Equal(t, 1, countDevices(t, conn), "no new row, no replacement")
	filled := fetchDevice(t, conn, holderID)
	require.Equal(t, "aa:bb:cc:dd:ee:20", filled.MAC, "mac filled on the existing row")
	require.Equal(t, "online", filled.Status)
}
