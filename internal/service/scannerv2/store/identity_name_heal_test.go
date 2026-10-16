// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package store

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestApplyDeviceIdentity_GarbageNameHeal pins the 1c heal: a row named by
// pre-gate mojibake (control runes from a broken NBNS/mDNS decoder or a
// passive DNS-sighting name) is overwritten by the next scan's clean name —
// the fill-when-empty name CASE alone would keep the junk forever. A
// plausible stored name (including a user edit) is never touched.
func TestApplyDeviceIdentity_GarbageNameHeal(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	mac := "aa:bb:cc:dd:ee:42"

	// Row carrying the field-found garbage name — and the same mojibake as
	// its scan_attributes.hostname, which the merge-keep-old json_patch
	// semantics would preserve forever.
	devID := seedDeviceRow(t, conn, "10.0.0.42", mac, nid)
	garbage := "L\x14ÿ.tail1a481.ts.net"
	seedAttrs, err := json.Marshal(map[string]any{
		"hostname": garbage, "vendor": "Acme", "mac": "aa:bb:cc:dd:ee:42",
	})
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET name = ?, scan_attributes = ? WHERE id = ?`,
		garbage, string(seedAttrs), devID)
	require.NoError(t, err)

	// Next scan arrives with a clean name.
	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, IP: "10.0.0.42", MAC: mac, NetworkID: nid,
		Name:               "winhomepc.tail1a481.ts.net",
		ScanAttributesJSON: "{}",
	})
	require.NoError(t, err)
	var name string
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT name FROM devices WHERE id = ?`, devID).Scan(&name))
	require.Equal(t, "winhomepc.tail1a481.ts.net", name, "garbage name healed to the scan's clean name")
	var attrsRaw string
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT scan_attributes FROM devices WHERE id = ?`, devID).Scan(&attrsRaw))
	var attrs map[string]any
	require.NoError(t, json.Unmarshal([]byte(attrsRaw), &attrs))
	require.NotContains(t, attrs, "hostname", "garbage attr hostname stripped by the heal")
	require.Equal(t, "Acme", attrs["vendor"], "sibling attribute keys survive the strip")

	// A scan with NO name still heals: the IP is the honest fallback.
	_, err = conn.ExecContext(ctx, `UPDATE devices SET name = ? WHERE id = ?`,
		"bad\x0bname", devID)
	require.NoError(t, err)
	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, IP: "10.0.0.42", MAC: mac, NetworkID: nid,
		ScanAttributesJSON: "{}",
	})
	require.NoError(t, err)
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT name FROM devices WHERE id = ?`, devID).Scan(&name))
	require.Equal(t, "10.0.0.42", name, "no-name scan heals garbage to the IP")

	// A plausible stored name (user edit) survives a name-less scan.
	_, err = conn.ExecContext(ctx, `UPDATE devices SET name = ? WHERE id = ?`,
		"书房台灯", devID)
	require.NoError(t, err)
	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, IP: "10.0.0.42", MAC: mac, NetworkID: nid,
		ScanAttributesJSON: "{}",
	})
	require.NoError(t, err)
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT name FROM devices WHERE id = ?`, devID).Scan(&name))
	require.Equal(t, "书房台灯", name, "plausible name (user edit) untouched")

	// The attr strip is independent of the name state: a row whose name was
	// already healed (e.g. by a build that lacked the strip) keeps the
	// garbage attr hostname; a plausible attr hostname under a plausible
	// name survives untouched.
	_, err = conn.ExecContext(ctx, `UPDATE devices SET scan_attributes = ? WHERE id = ?`,
		string(seedAttrs), devID)
	require.NoError(t, err)
	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, IP: "10.0.0.42", MAC: mac, NetworkID: nid,
		ScanAttributesJSON: "{}",
	})
	require.NoError(t, err)
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT scan_attributes FROM devices WHERE id = ?`, devID).Scan(&attrsRaw))
	require.NoError(t, json.Unmarshal([]byte(attrsRaw), &attrs))
	require.NotContains(t, attrs, "hostname", "garbage attr strips even when the name is already clean")
	require.Equal(t, "Acme", attrs["vendor"])

	goodAttrs, err := json.Marshal(map[string]any{"hostname": "书房台灯", "vendor": "Acme"})
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET scan_attributes = ? WHERE id = ?`,
		string(goodAttrs), devID)
	require.NoError(t, err)
	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, IP: "10.0.0.42", MAC: mac, NetworkID: nid,
		ScanAttributesJSON: "{}",
	})
	require.NoError(t, err)
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT scan_attributes FROM devices WHERE id = ?`, devID).Scan(&attrsRaw))
	require.NoError(t, json.Unmarshal([]byte(attrsRaw), &attrs))
	require.Equal(t, "书房台灯", attrs["hostname"], "plausible attr hostname survives the strip")
}

// TestApplyDeviceIdentity_JunkBrandHeal pins the 宁空勿错 heal semantics: a
// stored denylisted brand (rows branded from the HTTP Server header by
// pre-2026-10-17 builds) is replaced by the scan's real brand — or cleared
// outright when the scan carries none — while a curated brand survives
// every scan.
func TestApplyDeviceIdentity_JunkBrandHeal(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	mac := "aa:bb:cc:dd:ee:52"
	devID := seedDeviceRow(t, conn, "10.0.0.52", mac, nid)
	write := func(brand string) {
		_, err := conn.ExecContext(ctx, `UPDATE devices SET brand = ? WHERE id = ?`, brand, devID)
		require.NoError(t, err)
	}
	read := func() string {
		var brand string
		require.NoError(t, conn.QueryRowContext(ctx, `SELECT brand FROM devices WHERE id = ?`, devID).Scan(&brand))
		return brand
	}
	apply := func(brand string) {
		_, err := repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
			TargetID: devID, IP: "10.0.0.52", MAC: mac, NetworkID: nid,
			Brand: brand, ScanAttributesJSON: "{}",
		})
		require.NoError(t, err)
	}

	// No-brand scan clears a denylisted stored brand (the rig's five
	// nginx rows are exactly this shape).
	write("nginx")
	apply("")
	require.Empty(t, read(), "brand-less scan clears the web-server junk brand")

	// A real brand still overwrites directly.
	write("MiniDLNA")
	apply("QNAP Systems")
	require.Equal(t, "QNAP Systems", read(), "real brand replaces junk")

	// Letter-less junk clears too.
	write("0,1,2")
	apply("")
	require.Empty(t, read(), "brand-less scan clears letter-less junk")

	// A curated brand (user edit) survives both scan shapes.
	write("书房NAS")
	apply("")
	require.Equal(t, "书房NAS", read(), "curated brand never clobbered by a brand-less scan")
	apply("Espressif")
	require.Equal(t, "书房NAS", read(), "curated brand never clobbered by a scan brand")
}
