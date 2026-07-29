// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package changedetect

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"

	"github.com/stretchr/testify/require"
)

// TestDiff_NoChangeWhenOnlyVolatileKeysDiffer is the regression test for the
// change_log noise storm: two snapshots whose scan_attributes differ ONLY in
// volatile keys (timestamps, transient counters, AND now the scanner-inferred
// identity echoes like hostname/inferred_type that wobble with probe success)
// must NOT register as a change. On the test env the timestamp subtype alone
// produced 53587 bogus device_changed rows in ~2 days; the inferred-key subtype
// produced another large batch (scan_attributes wobble was 81% of all noise).
func TestDiff_NoChangeWhenOnlyVolatileKeysDiffer(t *testing.T) {
	before := snapshotWithAttrs(t, `{"vendor":"nginx","hostname":"h1","last_scanned_at":"2026-07-22T13:47:29Z","last_scan_rtt_ms":12,"inferred_type":"server","inferred_type_source":"protocol"}`)
	after := snapshotWithAttrs(t, `{"vendor":"nginx","hostname":"h2-other","last_scanned_at":"2026-07-22T13:57:29Z","last_scan_rtt_ms":45,"inferred_type":"embedded","inferred_type_source":"heuristic"}`)

	require.Nil(t, Diff(before, after), "snapshots differing only in volatile keys must not diff")
	require.Nil(t, DiffIdentity(before, after), "identity diff must be nil for volatile-only changes")
	require.Nil(t, DiffClassification(before, after), "classification diff must be nil after volatile-key stripping")
}

// TestDiff_DetectsRealAttributeChange ensures a genuine scan_attributes change
// (e.g. vendor re-identified) still surfaces after volatile-key stripping.
func TestDiff_DetectsRealAttributeChange(t *testing.T) {
	before := snapshotWithAttrs(t, `{"vendor":"nginx","last_scanned_at":"2026-07-22T13:47:29Z"}`)
	after := snapshotWithAttrs(t, `{"vendor":"apache","last_scanned_at":"2026-07-22T13:57:29Z"}`)

	diff := Diff(before, after)
	require.NotNil(t, diff)
	require.Contains(t, diff, "scan_attributes")
}

// TestDiff_KeyOrderIndependent confirms the normalizer canonicalizes key order
// so a re-serialization of the same logical content compares equal.
func TestDiff_KeyOrderIndependent(t *testing.T) {
	before := snapshotWithAttrs(t, `{"vendor":"nginx","hostname":"h1"}`)
	after := snapshotWithAttrs(t, `{"hostname":"h1","vendor":"nginx"}`)

	require.Nil(t, Diff(before, after))
}

// TestNormalizeScanAttrs_EdgeCases guards the parse-failure passthrough.
func TestNormalizeScanAttrs_EdgeCases(t *testing.T) {
	require.Equal(t, "", normalizeScanAttrs(""))
	require.Equal(t, "not-json", normalizeScanAttrs("not-json"))
	// A JSON array (the corrupted array-form seen in production data) is not a
	// JSON object — it must pass through unchanged so it still diffs as a real
	// change rather than silently masking corruption.
	require.Equal(t, `["{...}","{...}"]`, normalizeScanAttrs(`["{...}","{...}"]`))
}

// TestDiffIdentity_StatusExcluded is the regression test for the liveness/
// identity conflation: an offline→online (or online→offline) status flip MUST
// NOT register as a device_changed event. status is a liveness signal owned by
// the heartbeat service and the device_lost/device_recovered topology events —
// it must never single-handedly trip device_changed. This was the core of the
// flap loop (one device_lost + one device_changed per flap cycle).
func TestDiffIdentity_StatusExcluded(t *testing.T) {
	before := DeviceSnapshot{Name: "h1", Type: "server", Status: "offline"}
	after := DeviceSnapshot{Name: "h1", Type: "server", Status: "online"}

	require.Nil(t, DiffIdentity(before, after), "a pure status flip must not be an identity change")
	// The legacy Diff (identity ∪ classification) also excludes status now.
	require.Nil(t, Diff(before, after), "status must be excluded from all diff variants")
}

// TestDiffIdentity_DetectsRealIdentityChange confirms a genuine identity change
// (e.g. a router swap renamed the device) still surfaces via DiffIdentity,
// while the classification-only wobble (open_ports/services) goes to
// DiffClassification instead of triggering device_changed.
func TestDiffIdentity_DetectsRealIdentityChange(t *testing.T) {
	before := DeviceSnapshot{
		Name: "NanoPiR4S", Type: "router", Brand: "FriendlyELEC",
		OpenPorts: "[{\"port\":22}]", DetectedServices: "[{\"port\":22}]",
	}
	after := DeviceSnapshot{
		Name: "GL-MT3000", Type: "router", Brand: "GL.iNet",
		OpenPorts: "[{\"port\":22},{\"port\":53}]", DetectedServices: "[{\"port\":22},{\"port\":53}]",
	}

	idDiff := DiffIdentity(before, after)
	require.NotNil(t, idDiff)
	require.Contains(t, idDiff, "name")
	require.Contains(t, idDiff, "brand")
	require.NotContains(t, idDiff, "open_ports", "open_ports is classification-tier, not identity")

	clsDiff := DiffClassification(before, after)
	require.NotNil(t, clsDiff)
	require.Contains(t, clsDiff, "open_ports")
	require.NotContains(t, clsDiff, "name", "name is identity-tier, not classification")
}

// TestDiffClassification_PortsOnlyWobble confirms run-to-run port/service wobble
// (a probe that timed out this scan) lands in classification diff only, never
// tripping the identity gate. This is what stops the 50%+ open_ports /
// detected_services noise from manufacturing device_changed rows.
func TestDiffClassification_PortsOnlyWobble(t *testing.T) {
	before := DeviceSnapshot{
		Name: "jetson", Type: "server",
		OpenPorts: "[{\"port\":22},{\"port\":5900}]", DetectedServices: "[{\"port\":22}]",
	}
	after := DeviceSnapshot{
		Name: "jetson", Type: "server",
		OpenPorts: "[{\"port\":22}]", DetectedServices: "[{\"port\":22},{\"port\":5900}]",
	}

	require.Nil(t, DiffIdentity(before, after), "port wobble must not be an identity change")
	cls := DiffClassification(before, after)
	require.NotNil(t, cls)
	require.Contains(t, cls, "open_ports")
	require.Contains(t, cls, "detected_services")
}

// TestDBRecorder_CooldownDedup verifies that repeated device_changed events for
// the same device within the cooldown window are suppressed, while
// device_added/device_lost always emit. This is the second line of defense
// against the noise storm (after field tiering): even an identity field that
// genuinely flaps every scan is limited to one event per cooldown window.
func TestDBRecorder_CooldownDedup(t *testing.T) {
	// Use an in-memory SQLite + the real sqlc queries to exercise the full path.
	dbConn, queries := setupTestDB(t)
	defer dbConn.Close()
	rec := NewDBRecorder(queries, nil, time.Minute, nil) // 1m cooldown
	ctx := context.Background()

	// Seed a device to attach changes to.
	dev, err := queries.CreateDevice(ctx, db.CreateDeviceParams{
		Name: "d1", Type: "server", IpAddress: "10.0.0.1", Status: "online",
		// CHECK(json_valid) columns require valid JSON; empty string fails.
		UserAttributes: "{}", Tags: "[]",
	})
	require.NoError(t, err)

	// First device_changed emits.
	rec.Record(ctx, ChangeEvent{
		ChangeType: ChangeTypeDeviceChanged, EntityType: EntityTypeDevice,
		DeviceID: dev.ID, Before: DeviceSnapshot{Name: "d1"}, After: DeviceSnapshot{Name: "d1x"},
	})
	count := countChangeLog(t)
	require.Equal(t, 1, count, "first device_changed should emit")

	// Second device_changed within cooldown is suppressed.
	rec.Record(ctx, ChangeEvent{
		ChangeType: ChangeTypeDeviceChanged, EntityType: EntityTypeDevice,
		DeviceID: dev.ID, Before: DeviceSnapshot{Name: "d1x"}, After: DeviceSnapshot{Name: "d1y"},
	})
	require.Equal(t, 1, countChangeLog(t), "second device_changed within cooldown suppressed")

	// device_lost is NOT throttled — always emits.
	rec.Record(ctx, ChangeEvent{
		ChangeType: ChangeTypeDeviceLost, EntityType: EntityTypeDevice,
		DeviceID: dev.ID, Before: DeviceSnapshot{Name: "d1y"},
	})
	require.Equal(t, 2, countChangeLog(t), "device_lost must always emit")
}

func snapshotWithAttrs(t *testing.T, attrs string) DeviceSnapshot {
	t.Helper()
	require.NoError(t, json.Unmarshal([]byte(attrs), &map[string]any{}))
	return SnapshotFromDevice(db.Device{ScanAttributes: attrs})
}

// setupTestDB opens an in-memory SQLite with the full schema (devices +
// change_log) and returns the connection + sqlc Queries. Used by recorder tests
// that exercise the real DBRecorder insert path.
func setupTestDB(t *testing.T) (*sql.DB, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	testDBConn = conn // for countChangeLog's raw COUNT
	return conn, db.New(conn)
}

// countChangeLog returns the total change_log row count via a raw COUNT query on
// the test's connection, sidestepping the sentinel params of the sqlc
// CountChangeLog query (whose interface{} sentinels interact unpredictably with
// the driver's NULL handling).
func countChangeLog(t *testing.T) int {
	t.Helper()
	row := testDBConn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM change_log")
	var n int
	require.NoError(t, row.Scan(&n))
	return n
}

// testDBConn holds the connection opened by setupTestDB, so countChangeLog can
// run a raw COUNT without re-deriving it from the Queries.
var testDBConn *sql.DB
