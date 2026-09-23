// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You should use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// insertLeaseDevice inserts a device row directly (bypassing the bridge) so
// tests can construct identity tangles the bridge itself wouldn't produce;
// e.g. two rows at one IP, a stale pre-roam row, or a NULL-mac sighting.
func insertLeaseDevice(t *testing.T, conn *sql.DB, networkID int64, ip, mac, uuid, lastSeen string) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO devices (name, ip_address, mac_address, device_uuid, network_id, status, last_seen)
		 VALUES (?, ?, ?, ?, ?, 'online', ?)`,
		ip, ip, mac, uuid, networkID, lastSeen)
	require.NoError(t, err)
}

// dropIPNetworkUnique removes the composite identity constraint for tests
// that seed pre-constraint "identity tangles" (two rows at one
// (ip, network_id)), shapes legacy databases carried before the UNIQUE index
// and that manual sqlite surgery can still produce. The resolution logic
// under test must stay defensive against them.
func dropIPNetworkUnique(t *testing.T, conn *sql.DB) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(), `DROP INDEX IF EXISTS idx_devices_ip_network`)
	require.NoError(t, err)
}

// TestResolveDeviceUUID_MacPrimaryOverSharedIP is the #389 knot: two rows share
// an IP (a stale pre-roam row and the row currently live at that IP). The
// sighting's MAC must pick the live row's uuid, the old LIMIT-1-without-ORDER
// lookup could feed the stale row's lease forever, keeping it online while the
// real row aged.
func TestResolveDeviceUUID_MacPrimaryOverSharedIP(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	dropIPNetworkUnique(t, conn)

	insertLeaseDevice(t, conn, agentNetID, "192.168.62.41", "aa:bb:cc:dd:ee:41", "uuid-stale", "2026-09-01T00:00:00Z")
	insertLeaseDevice(t, conn, agentNetID, "192.168.62.41", "aa:bb:cc:dd:ee:99", "uuid-live", "2026-09-18T00:00:00Z")

	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor("192.168.62.41", "pc", "", "aa:bb:cc:dd:ee:99"),
	})

	var snapUUID string
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT device_uuid FROM scan_snapshots WHERE ip = ? AND network_id = ?`, "192.168.62.41", agentNetID).Scan(&snapUUID))
	require.Equal(t, "uuid-live", snapUUID, "lease must follow the MAC-matched (live) row, not the arbitrary row at the IP")
}

// Without a MAC the resolver falls back to the IP lookup, and among rows
// sharing that IP the most-recently-seen one wins (recency, not insertion
// order).
func TestResolveDeviceUUID_RecencyFallbackWithoutMAC(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	dropIPNetworkUnique(t, conn)

	insertLeaseDevice(t, conn, agentNetID, "192.168.62.42", "aa:bb:cc:dd:ee:01", "uuid-older", "2026-09-01T00:00:00Z")
	insertLeaseDevice(t, conn, agentNetID, "192.168.62.42", "", "uuid-newer", "2026-09-18T00:00:00Z")

	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor("192.168.62.42", "pc", "", ""), // no MAC on the sighting
	})

	var snapUUID string
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT device_uuid FROM scan_snapshots WHERE ip = ? AND network_id = ?`, "192.168.62.42", agentNetID).Scan(&snapUUID))
	require.Equal(t, "uuid-newer", snapUUID)
}

// RecordAliveSnapshots must also stamp devices.last_seen: the agent→center
// stable-hash fast path refreshes leases WITHOUT the device bridge, so without
// this stamp a stable network's device rows show ever-aging last_seen (#389).
func TestRecordAliveSnapshots_StampsDeviceLastSeen(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}

	insertLeaseDevice(t, conn, agentNetID, "192.168.62.43", "aa:bb:cc:dd:ee:43", "uuid-fresh", "2026-09-01T00:00:00Z")

	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor("192.168.62.43", "pc", "", "aa:bb:cc:dd:ee:43"),
	})

	var lastSeen string
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT last_seen FROM devices WHERE device_uuid = ?`, "uuid-fresh").Scan(&lastSeen))
	stamped, err := time.Parse(time.RFC3339, lastSeen)
	require.NoError(t, err, "last_seen should be RFC3339-stamped, got %q", lastSeen)
	seedTime := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	require.True(t, stamped.After(seedTime), "last_seen should advance past the pre-seed value, got %q", lastSeen)
	require.WithinDuration(t, time.Now().UTC(), stamped, 5*time.Second, "stamp should be current, got %q", lastSeen)
}
