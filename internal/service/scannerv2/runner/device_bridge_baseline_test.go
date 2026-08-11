// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package runner

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/testutil"
)

// These characterization tests pin behaviors that the #159 consolidation
// (moving device_bridge.go's raw SQL onto the Repository interface) must
// preserve. They exist because a survey of the two identity-writing paths
// (device_bridge.go vs store.RecordDevice) found these behaviors load-bearing
// but UNTESTED — a refactor without a baseline could silently regress them.
//
// This file adds NO production code; it only locks current behavior so PR 2 of
// #159 (the actual SQL move) has a safety net.

// reportForTyped builds a HostReport with an explicit inferred_type_source
// ("protocol" / "heuristic" / "") — reportFor omits it, so tests of
// applyTypeStickiness (which keys on the stored source) need this variant.
func reportForTyped(ip, devType, brand, mac, typeSource string) scannerv2.HostReport {
	r := reportFor(ip, devType, brand, mac)
	r.Device.Fields["inferred_type_source"] = typeSource
	return r
}

// baselineDeviceRow extends deviceRow with the type column for the type-
// stickiness assertions.
type baselineDeviceRow struct {
	ID    int64
	IP    string
	MAC   string
	Type  string
	Brand string
	Name  string
}

func fetchBaselineDevice(t *testing.T, conn *sql.DB, ip string) baselineDeviceRow {
	t.Helper()
	var r baselineDeviceRow
	err := conn.QueryRow(
		`SELECT id, ip_address, mac_address, type, brand, name FROM devices WHERE ip_address = ?`, ip).
		Scan(&r.ID, &r.IP, &r.MAC, &r.Type, &r.Brand, &r.Name)
	require.NoError(t, err)
	return r
}

// TestApplyDeviceBridge_TypeStickiness_PreservesProtocolType is the
// characterization test for applyTypeStickiness (device_bridge.go:408). A
// device previously identified by PROTOCOL evidence (SNMP/RTSP/ONVIF —
// trustworthy) must NOT downgrade to a weaker type just because one rescan's
// protocol probe timed out (yielding only a heuristic/unknown verdict). This
// is the core anti-flap mechanism; dropping it would reintroduce the
// other↔router type churn the bridge explicitly fights.
func TestApplyDeviceBridge_TypeStickiness_PreservesProtocolType(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// Scan 1: SNMP-classified router (protocol source).
	_, _ = rn.applyDeviceBridge(ctx,
		reportForTyped("10.0.0.1", "router", "cisco", "aa:bb:cc:dd:ee:01", "protocol"),
		rn.networkID, "")

	// Scan 2: same device, MAC/IP identical, but this time the protocol probe
	// failed so only a weak "other" heuristic verdict is available. The stored
	// "router" (protocol) type MUST survive.
	_, _ = rn.applyDeviceBridge(ctx,
		reportForTyped("10.0.0.1", "other", "cisco", "aa:bb:cc:dd:ee:01", "heuristic"),
		rn.networkID, "")

	require.Equal(t, 1, countDevices(t, conn), "same device, no split")
	d := fetchBaselineDevice(t, conn, "10.0.0.1")
	require.Equal(t, "router", d.Type,
		"protocol-stored type must survive a heuristic-only rescan (anti-flap)")
}

// TestApplyDeviceBridge_RealTypeIsStickyOnRescan pins a DUAL-GATE behavior the
// survey uncovered: applyTypeStickiness (Go) would allow a protocol→protocol
// re-identification, BUT buildExistingUpdate's SQL CASE guard
// (device_bridge.go:703 — `type = CASE WHEN (type=” OR 'unknown' OR 'other')
// AND ?!=” THEN ? ELSE type`) blocks ANY change once a real (non-empty/
// non-unknown/non-other) type is stored. The net effect: a normal re-scan
// NEVER transitions one real type to another (e.g. embedded→router); only
// unknown/other types are refinable. This is a subtle, load-bearing
// interaction that a consolidation could silently break.
func TestApplyDeviceBridge_RealTypeIsStickyOnRescan(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	_, _ = rn.applyDeviceBridge(ctx,
		reportForTyped("10.0.0.2", "embedded", "", "aa:bb:cc:dd:ee:02", "protocol"),
		rn.networkID, "")
	// Re-scan: even a protocol-sourced re-identification to "router" does NOT
	// overwrite the stored "embedded" — the SQL CASE keeps the first real type.
	_, _ = rn.applyDeviceBridge(ctx,
		reportForTyped("10.0.0.2", "router", "", "aa:bb:cc:dd:ee:02", "protocol"),
		rn.networkID, "")

	d := fetchBaselineDevice(t, conn, "10.0.0.2")
	require.Equal(t, "embedded", d.Type,
		"a stored REAL type must survive any normal re-scan (SQL CASE guard + Go stickiness, dual-gate)")
}

// TestApplyDeviceBridge_HeuristicTypeIsRefinable confirms a heuristic-stored
// type IS refinable by a later scan (stickiness only protects "protocol"
// sources — a heuristic type may improve as more evidence arrives).
func TestApplyDeviceBridge_HeuristicTypeIsRefinable(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	_, _ = rn.applyDeviceBridge(ctx,
		reportForTyped("10.0.0.3", "other", "", "aa:bb:cc:dd:ee:03", "heuristic"),
		rn.networkID, "")
	_, _ = rn.applyDeviceBridge(ctx,
		reportForTyped("10.0.0.3", "camera", "hikvision", "aa:bb:cc:dd:ee:03", "protocol"),
		rn.networkID, "")

	d := fetchBaselineDevice(t, conn, "10.0.0.3")
	require.Equal(t, "camera", d.Type,
		"heuristic-stored type must accept a stronger later verdict")
}

// TestApplyDeviceBridge_RoamToOccupiedIP_Characterization pins the ACTUAL
// behavior (captured by this baseline test) when a MAC-bearing device roams to
// an IP occupied by a stale mac-less placeholder: the bridge does NOT evict the
// placeholder in this scenario — the roaming device stays on its old IP and the
// placeholder persists, yielding a SPLIT (2 devices for 1 physical host). The
// roam-retry eviction path (device_bridge.go:261-286) is intended to handle
// exactly this, but the survey found it does not fire here. This test locks the
// current (buggy) behavior so #159 PR 2 can decide whether to fix it or preserve
// it — silently changing it during the SQL consolidation would be wrong either way.
//
// NOTE: this is a KNOWN-GAP characterization, not a correctness assertion. If
// #159 PR 2 fixes the eviction, this test should be flipped to assert count==1.
func TestApplyDeviceBridge_RoamToOccupiedIP_Characterization(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// Seed a real device at .10 with a MAC.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("192.168.63.10", "camera", "hikvision", "de:ad:be:ef:10:10"),
		rn.networkID, "")

	// Seed a stale mac-less placeholder at .20 (occupying the roam target).
	_, err := conn.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, scan_source,
		scan_attributes, network_id, first_seen, last_seen, last_scanned_at, created_at, updated_at)
		VALUES ('192.168.63.20','other','192.168.63.20','','online','scanner_v2','{}',?,?,?,?,?,?)`,
		rn.networkID, baselineNow(), baselineNow(), baselineNow(), baselineNow(), baselineNow())
	require.NoError(t, err)

	// The .10 device roams to .20 (same MAC). Current behavior: the roam target
	// (.20) is occupied by the mac-less placeholder; the eviction-retry path
	// does NOT fire, so the device splits into two rows.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("192.168.63.20", "camera", "hikvision", "de:ad:be:ef:10:10"),
		rn.networkID, "")

	require.Equal(t, 2, countDevices(t, conn),
		"characterization: roam to an occupied IP currently SPLITS (eviction does not fire) — known gap")
	// The original device keeps its MAC + old IP (the bridge updated its other
	// fields but could not relocate the IP).
	orig := fetchBaselineDevice(t, conn, "192.168.63.10")
	require.Equal(t, "de:ad:be:ef:10:10", orig.MAC,
		"the original device row keeps its MAC (identity stable), just didn't relocate")
}

// TestApplyDeviceBridge_NullNetworkID pins the legacy single-instance identity
// path (networkID.Valid == false). Before multi-network support, devices had no
// network_id; the bridge must still resolve + upsert them via the
// network_id IS NULL branches. This is the path an instance runs when no network
// is configured (some standalone deployments).
func TestApplyDeviceBridge_NullNetworkID(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	// Runner with NO network (mirrors standalone pre-network-config startup).
	rn := New(nil, queries, conn, nil, 0, nil)
	rn.networkID = sql.NullInt64{} // explicit: NULL network
	rn.SetChangeRecorder(changedetect.NewDBRecorder(queries, nil, 0, nil))
	ctx := context.Background()

	// First discovery — INSERT with network_id NULL.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("172.16.0.5", "embedded", "", "aa:bb:cc:dd:ee:05"),
		rn.networkID, "")
	require.Equal(t, 1, countDevices(t, conn))

	// Rescan — resolve via the NULL-network lookup, UPDATE in place (no split).
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("172.16.0.5", "embedded", "raspberry", "aa:bb:cc:dd:ee:05"),
		rn.networkID, "")
	require.Equal(t, 1, countDevices(t, conn), "rescan must not split the device")

	var nid sql.NullInt64
	var mac string
	require.NoError(t, conn.QueryRow(
		`SELECT network_id, mac_address FROM devices WHERE ip_address = '172.16.0.5'`).Scan(&nid, &mac))
	require.False(t, nid.Valid, "network_id must remain NULL on the legacy path")
	require.Equal(t, "aa:bb:cc:dd:ee:05", mac)
}

// TestRecordDevice_OverlapsBridge_ForceOverwriteWins pins the column-overlap
// behavior between store.RecordDevice (force-overwrite mac/brand) and the
// bridge (fill-when-empty), which run sequentially on every scan (store first
// in the orchestrator, then the bridge in the runner). The current NET effect
// is that RecordDevice's force-overwrite lands first and the bridge's
// fill-when-empty guards then see a non-empty value and skip. A consolidation
// that moves identity writing onto the Repository must preserve this net effect
// — otherwise mac/brand semantics flip for every overlapping rescan.
func TestRecordDevice_OverlapsBridge_ForceOverwriteWins(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// Scan 1: device discovered with MAC=A, brand=X via the bridge.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("10.0.0.9", "embedded", "vendor-x", "aa:bb:cc:dd:ee:09"),
		rn.networkID, "")

	// Scan 2: the orchestrator's RecordDevice runs FIRST (as it does in
	// production) with an UPDATED MAC=B and brand=Y, then the bridge runs.
	var nid int64
	if rn.networkID.Valid {
		nid = rn.networkID.Int64
	}
	repo := store.NewSQLiteRepository(conn, store.Options{NetworkID: nid}, nil)
	require.NoError(t, repo.RecordDevice(ctx, "10.0.0.9", scannerv2.DeviceRef{
		IP:    "10.0.0.9",
		Type:  "embedded",
		Brand: "vendor-y",
		Fields: map[string]string{
			"mac": "bb:bb:bb:bb:bb:09",
		},
	}))
	// Then the bridge runs (rescan with the identity it stored).
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("10.0.0.9", "embedded", "vendor-x", "aa:bb:cc:dd:ee:09"),
		rn.networkID, "")

	// NET effect: RecordDevice's force-overwrite of mac=B / brand=Y wins
	// (it landed first; the bridge's fill-when-empty guards skipped because the
	// stored value was now non-empty). Pin this so the consolidation preserves it.
	d := fetchBaselineDevice(t, conn, "10.0.0.9")
	require.Equal(t, "vendor-y", d.Brand,
		"RecordDevice force-overwrite of brand must win over the bridge's fill-when-empty (sequence-order net effect)")
	require.Equal(t, "bb:bb:bb:bb:bb:09", d.MAC,
		"RecordDevice force-overwrite of mac must win over the bridge's fill-when-empty (sequence-order net effect)")
}

// baselineNow is a fixed timestamp string for direct INSERT helpers in these
// baseline tests. Kept local + uniquely named to avoid colliding with helpers
// in other test files of this package.
func baselineNow() string {
	return "2026-08-11T00:00:00Z"
}
