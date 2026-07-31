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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestApplyDeviceBridge_LastSeenAdvancesOnRescan is the regression test for the
// last_seen bug: the re-scan UPDATEs used `last_seen = COALESCE(last_seen, ?)`,
// which only backfills a NULL and never advances an already-set value — so a
// known device's last_seen froze at first-discovery time forever. The fix
// (`last_seen = ?`) makes each alive re-scan refresh it to now, restoring the
// documented "last observed ONLINE by a scan" semantics (which the liveness-
// visibility feature now exposes in the API).
func TestApplyDeviceBridge_LastSeenAdvancesOnRescan(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// First scan: device discovered, last_seen stamped ~now.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("192.168.63.10", "camera", "hikvision", "aa:bb:cc:dd:ee:10"), rn.networkID, "")
	var devID int64
	require.NoError(t, conn.QueryRow(
		`SELECT id FROM devices WHERE mac_address='aa:bb:cc:dd:ee:10'`).Scan(&devID))

	var firstSeen time.Time
	require.NoError(t, conn.QueryRow(`SELECT last_seen FROM devices WHERE id=?`, devID).Scan(&firstSeen))
	require.False(t, firstSeen.IsZero(), "first scan stamps last_seen")

	// Backdate last_seen to simulate the old bug state (frozen at an old time),
	// then re-scan alive. The fix must advance last_seen to ~now, not leave it.
	old := time.Now().UTC().Add(-24 * time.Hour)
	_, err := conn.ExecContext(ctx, `UPDATE devices SET last_seen=? WHERE id=?`, old, devID)
	require.NoError(t, err)

	// Re-scan the same alive device.
	_, _ = rn.applyDeviceBridge(ctx,
		reportFor("192.168.63.10", "camera", "hikvision", "aa:bb:cc:dd:ee:10"), rn.networkID, "")

	var after time.Time
	require.NoError(t, conn.QueryRow(`SELECT last_seen FROM devices WHERE id=?`, devID).Scan(&after))
	// Must have advanced well past the backdated 24h-ago value (within the last
	// minute of now). Under the old COALESCE bug it would have stayed at `old`.
	require.True(t, after.Sub(old) > 23*time.Hour, "last_seen must advance on alive re-scan (was %v, now %v)", old, after)
	require.WithinDuration(t, time.Now().UTC(), after, 2*time.Minute, "last_seen refreshed to ~now")
}
