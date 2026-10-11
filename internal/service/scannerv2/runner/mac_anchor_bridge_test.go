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
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// The chassis-anchor bridge contract (#522): a MAC-only synthesized report
// (anchor-sentinel IP) creates a device row keyed by MAC, seeds no probe
// heartbeat (there is no address to probe yet), and falls back to the MAC for
// the display name. When a later scan fills in the real IP, the row roams
// onto it and the ICMP fallback heartbeat is seeded at that point.

func TestApplyDeviceBridge_ChassisAnchorCreate(t *testing.T) {
	rn, queries, conn := setupChangeDetectDB(t)
	hb := &hbStub{}
	rn.heartbeat = hb

	mac := "aa:bb:cc:dd:ee:51"
	rep := reportFor(scannerv2.AnchorIP(mac), "", "", mac)

	isNew, _ := rn.applyDeviceBridge(t.Context(), rep, rn.networkID, "")
	require.True(t, isNew)

	var ip, rowMAC, name string
	require.NoError(t, conn.QueryRow(
		`SELECT ip_address, mac_address, name FROM devices WHERE mac_address = ?`, mac).
		Scan(&ip, &rowMAC, &name))
	require.Equal(t, scannerv2.AnchorIP(mac), ip, "row holds the anchor sentinel until an address lands")
	require.Equal(t, mac, rowMAC)
	require.Equal(t, mac, name, "no hostname and a sentinel IP: the display name falls back to the MAC")
	require.Empty(t, hb.defaultCfgCalls, "no IP to probe: no ICMP fallback heartbeat at creation")
	require.Empty(t, hb.createCfgCalls)

	// A chassis-first device is still a device_added change event.
	events, err := queries.ListChangeLog(t.Context(), dbListAllParams())
	require.NoError(t, err)
	require.NotEmpty(t, events, "chassis anchor must emit device_added")
	require.Equal(t, "device_added", events[len(events)-1].ChangeType)
}

func TestApplyDeviceBridge_ChassisAnchorGainsIP(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	mac := "aa:bb:cc:dd:ee:52"

	// Chassis first: row created with the sentinel.
	_, _ = rn.applyDeviceBridge(t.Context(), reportFor(scannerv2.AnchorIP(mac), "switch", "", mac), rn.networkID, "")

	// The scan that finally reaches the device fills in the real address.
	hb := &hbStub{}
	rn.heartbeat = hb
	_, _ = rn.applyDeviceBridge(t.Context(), reportFor("10.0.0.52", "switch", "", mac), rn.networkID, "")

	var ip string
	require.NoError(t, conn.QueryRow(
		`SELECT ip_address FROM devices WHERE mac_address = ?`, mac).Scan(&ip))
	require.Equal(t, "10.0.0.52", ip, "MAC-primary identity must roam the anchored row onto the real address")

	var cfgs int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ?`, mac).Scan(&cfgs))
	require.EqualValues(t, 1, cfgs, "still one row after the fill, not a duplicate")
	require.Len(t, hb.defaultCfgCalls, 1, "the ICMP fallback heartbeat is seeded when the address lands")
}

func TestApplyDeviceBridge_ChassisResightingKeepsAddress(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	mac := "aa:bb:cc:dd:ee:53"

	// Device known WITH a real address; repeated chassis-only sightings must
	// not read as a roam and blank it.
	_, _ = rn.applyDeviceBridge(t.Context(), reportFor("10.0.0.53", "camera", "", mac), rn.networkID, "")
	_, _ = rn.applyDeviceBridge(t.Context(), reportFor(scannerv2.AnchorIP(mac), "camera", "", mac), rn.networkID, "")
	_, _ = rn.applyDeviceBridge(t.Context(), reportFor("", "camera", "", mac), rn.networkID, "")

	var ip string
	require.NoError(t, conn.QueryRow(
		`SELECT ip_address FROM devices WHERE mac_address = ?`, mac).Scan(&ip))
	require.Equal(t, "10.0.0.53", ip)

	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ?`, mac).Scan(&n))
	require.EqualValues(t, 1, n, "no duplicate rows from chassis re-sightings")
}

// TestApplyDeviceBridge_DisplayNameFallback: the display-name chain ends at
// the report IP; when that IP is an anchor sentinel (or empty) the MAC is the
// honest last resort, never the sentinel string itself.
func TestApplyDeviceBridge_DisplayNameFallback(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:54"
	require.Equal(t, mac, deviceDisplayName(reportFor(scannerv2.AnchorIP(mac), "", "", mac), mac))
	require.Equal(t, mac, deviceDisplayName(reportFor("", "", "", mac), mac))
	require.Equal(t, "10.0.0.54", deviceDisplayName(reportFor("10.0.0.54", "", "", mac), mac),
		"a real IP still wins over the MAC")
}
