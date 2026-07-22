// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package changedetect

import (
	"encoding/json"
	"testing"

	"mibee-steward/internal/db"

	"github.com/stretchr/testify/require"
)

// TestDiff_NoChangeWhenOnlyVolatileKeysDiffer is the regression test for the
// change_log noise storm: two snapshots whose scan_attributes differ ONLY in
// last_scanned_at / last_scan_rtt_ms (values that change every scan) must NOT
// register as a device_changed event. On the test env this single bug produced
// 53587 bogus device_changed rows in ~2 days.
func TestDiff_NoChangeWhenOnlyVolatileKeysDiffer(t *testing.T) {
	before := snapshotWithAttrs(t, `{"vendor":"nginx","hostname":"h1","last_scanned_at":"2026-07-22T13:47:29Z","last_scan_rtt_ms":12}`)
	after := snapshotWithAttrs(t, `{"vendor":"nginx","hostname":"h1","last_scanned_at":"2026-07-22T13:57:29Z","last_scan_rtt_ms":45}`)

	require.Nil(t, Diff(before, after), "snapshots differing only in volatile keys must not diff")
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

func snapshotWithAttrs(t *testing.T, attrs string) DeviceSnapshot {
	t.Helper()
	require.NoError(t, json.Unmarshal([]byte(attrs), &map[string]any{}))
	return SnapshotFromDevice(db.Device{ScanAttributes: attrs})
}
