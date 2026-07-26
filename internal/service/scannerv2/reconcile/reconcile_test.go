// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package reconcile

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/testutil"
)

// addNetwork inserts a networks row and returns its id.
func addNetwork(t *testing.T, db *sql.DB, name, cidr string) int64 {
	t.Helper()
	_, err := db.Exec(`INSERT INTO networks (name, cidr) VALUES (?, ?)`, name, cidr)
	require.NoError(t, err)
	var id int64
	require.NoError(t, db.QueryRow(`SELECT id FROM networks WHERE name = ?`, name).Scan(&id))
	return id
}

// addDevice inserts a devices row tagged with the given network_id.
func addDevice(t *testing.T, db *sql.DB, ip string, networkID int64) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO devices (name, ip_address, network_id, status, type) VALUES (?, ?, ?, 'online', 'other')`,
		ip, ip, networkID,
	)
	require.NoError(t, err)
}

func TestReconcile_DetectsOutOfNetworkDevices(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer dbConn.Close()

	// lan-62 with a cidr; one correctly-attributed device + one foreign (the
	// exact issue-#19 ghost pattern: a 63.x IP stamped on lan-62).
	net62 := addNetwork(t, dbConn, "lan-62", "192.168.62.0/24")
	addDevice(t, dbConn, "192.168.62.5", net62)  // in network — OK
	addDevice(t, dbConn, "192.168.63.20", net62) // OUT of network — mismatch

	// lan-63 with a cidr; all its devices are correctly inside.
	net63 := addNetwork(t, dbConn, "lan-63", "192.168.63.0/24")
	addDevice(t, dbConn, "192.168.63.1", net63)
	addDevice(t, dbConn, "192.168.63.100", net63)

	// lan-99 with NO cidr — its devices must be skipped (we don't know they're
	// wrong without a cidr to test against).
	net99 := addNetwork(t, dbConn, "lan-99", "")
	addDevice(t, dbConn, "10.0.0.5", net99)

	svc := New(dbConn, 0, nil, nil)
	mismatches, err := svc.Reconcile(context.Background())
	require.NoError(t, err)

	require.Len(t, mismatches, 1, "exactly the one ghost device on lan-62")
	m := mismatches[0]
	require.Equal(t, "192.168.63.20", m.IP)
	require.Equal(t, net62, m.NetworkID)
	require.Equal(t, "lan-62", m.Network)
	require.Equal(t, "192.168.62.0/24", m.CIDR)
}

func TestReconcile_NoCidrNetworkSkipped(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer dbConn.Close()

	// A network without cidr holding a clearly-foreign IP must NOT be flagged —
	// without a cidr we have no rule to test against. (The prerequisite backfill
	// is what fills these so they eventually become checkable.)
	net := addNetwork(t, dbConn, "no-cidr", "")
	addDevice(t, dbConn, "8.8.8.8", net)

	svc := New(dbConn, 0, nil, nil)
	mismatches, err := svc.Reconcile(context.Background())
	require.NoError(t, err)
	require.Empty(t, mismatches)
}

func TestReconcile_CorrectionClearsMismatches(t *testing.T) {
	// Simulate the operator fix: a ghost device is re-homed to the correct
	// network. The next reconcile must report zero mismatches (the gauge-style
	// reset semantics — not a lingering count).
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer dbConn.Close()

	net62 := addNetwork(t, dbConn, "lan-62", "192.168.62.0/24")
	net63 := addNetwork(t, dbConn, "lan-63", "192.168.63.0/24")
	addDevice(t, dbConn, "192.168.63.20", net62) // ghost on 62

	svc := New(dbConn, 0, nil, nil)
	m, err := svc.Reconcile(context.Background())
	require.NoError(t, err)
	require.Len(t, m, 1)

	// Operator re-homes the ghost to lan-63 (the fix).
	_, err = dbConn.Exec(`UPDATE devices SET network_id = ? WHERE ip_address = '192.168.63.20'`, net63)
	require.NoError(t, err)

	m, err = svc.Reconcile(context.Background())
	require.NoError(t, err)
	require.Empty(t, m, "after re-homing, no mismatches remain")
}

func TestReconcile_PicksUpBackfilledCidr(t *testing.T) {
	// A network that starts without a cidr (skipped) then gets one (via the
	// agent-report backfill) must become checkable on the next scan — the
	// refreshNetworks cache invalidates between scans.
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer dbConn.Close()

	net62 := addNetwork(t, dbConn, "lan-62", "")
	addDevice(t, dbConn, "192.168.63.20", net62)

	svc := New(dbConn, 0, nil, nil)
	m, err := svc.Reconcile(context.Background())
	require.NoError(t, err)
	require.Empty(t, m, "no cidr yet → skipped")

	// Backfill the cidr (as the agent-report path would).
	_, err = dbConn.Exec(`UPDATE networks SET cidr = '192.168.62.0/24' WHERE id = ?`, net62)
	require.NoError(t, err)

	m, err = svc.Reconcile(context.Background())
	require.NoError(t, err)
	require.Len(t, m, 1, "cidr now set → the ghost is detected")
}

// TestCleanupGhosts_RehomesWhenCanonicalExists covers the issue-#19 Layer 4
// startup migration: a ghost device on the wrong network is deleted BECAUSE a
// canonical copy exists in the correct network. No data loss.
func TestCleanupGhosts_RehomesWhenCanonicalExists(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer dbConn.Close()

	net62 := addNetwork(t, dbConn, "lan-62", "192.168.62.0/24")
	net63 := addNetwork(t, dbConn, "lan-63", "192.168.63.0/24")
	// Canonical copy on lan-63 (correct).
	addDevice(t, dbConn, "192.168.63.20", net63)
	// Ghost on lan-62 (wrong).
	addDevice(t, dbConn, "192.168.63.20", net62)
	// And a stale lease for the ghost on lan-62.
	_, err = dbConn.Exec(`INSERT INTO scan_snapshots (network_id, ip, mac, last_seen_at) VALUES (?, '192.168.63.20', '', '')`, net62)
	require.NoError(t, err)

	svc := New(dbConn, 0, nil, nil)
	stats, err := svc.CleanupGhosts(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, stats.Mismatches)
	require.Equal(t, 1, stats.Rehomed)
	require.Equal(t, 0, stats.Unresolved)

	// The ghost device is gone; the canonical copy remains.
	var n int64
	require.NoError(t, dbConn.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address = '192.168.63.20'`).Scan(&n))
	require.Equal(t, int64(1), n, "only the canonical (lan-63) row remains")
	// The ghost's lease is gone too.
	require.NoError(t, dbConn.QueryRow(`SELECT COUNT(*) FROM scan_snapshots WHERE network_id = ? AND ip = '192.168.63.20'`, net62).Scan(&n))
	require.Equal(t, int64(0), n, "ghost lease removed")

	// Idempotent: a second pass finds nothing.
	stats2, err := svc.CleanupGhosts(context.Background())
	require.NoError(t, err)
	require.Equal(t, 0, stats2.Mismatches)
}

// TestCleanupGhosts_LeavesUnresolvedWhenNoCanonical covers the safety case: a
// ghost with NO canonical copy is left alone (counted Unresolved), never
// auto-deleted — that would lose the only record.
func TestCleanupGhosts_LeavesUnresolvedWhenNoCanonical(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer dbConn.Close()

	net62 := addNetwork(t, dbConn, "lan-62", "192.168.62.0/24")
	addNetwork(t, dbConn, "lan-63", "192.168.63.0/24")
	// Ghost on lan-62, but NO copy on lan-63. Unsafe to auto-delete.
	addDevice(t, dbConn, "192.168.63.20", net62)

	svc := New(dbConn, 0, nil, nil)
	stats, err := svc.CleanupGhosts(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, stats.Mismatches)
	require.Equal(t, 0, stats.Rehomed)
	require.Equal(t, 1, stats.Unresolved)

	// The device is still there — left for the operator.
	var n int64
	require.NoError(t, dbConn.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address = '192.168.63.20'`).Scan(&n))
	require.Equal(t, int64(1), n)
}

// TestCleanupGhosts_MACFallback covers re-homing a ghost whose IP isn't in ANY
// configured cidr (so IP-containment can't find the canonical network), but
// whose MAC matches a device elsewhere — the MAC-primary identity rule.
func TestCleanupGhosts_MACFallback(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer dbConn.Close()

	net62 := addNetwork(t, dbConn, "lan-62", "192.168.62.0/24")
	net63 := addNetwork(t, dbConn, "lan-63", "192.168.63.0/24")
	// Canonical asset on lan-63 with a MAC.
	_, err = dbConn.Exec(`INSERT INTO devices (name, ip_address, mac_address, network_id, status, type) VALUES ('real', '192.168.63.20', 'aa:bb:cc:dd:ee:20', ?, 'online', 'other')`, net63)
	require.NoError(t, err)
	// Ghost on lan-62 with the SAME MAC but an IP in a THIRD subnet no network
	// owns (10.0.0.20) — IP-containment won't find a home, but MAC will.
	_, err = dbConn.Exec(`INSERT INTO devices (name, ip_address, mac_address, network_id, status, type) VALUES ('ghost', '10.0.0.20', 'aa:bb:cc:dd:ee:20', ?, 'online', 'other')`, net62)
	require.NoError(t, err)

	svc := New(dbConn, 0, nil, nil)
	stats, err := svc.CleanupGhosts(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, stats.Rehomed, "MAC fallback re-homes the ghost")
	require.Equal(t, 0, stats.Unresolved)

	// Canonical remains; ghost gone.
	var n int64
	require.NoError(t, dbConn.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:20'`).Scan(&n))
	require.Equal(t, int64(1), n)
}
