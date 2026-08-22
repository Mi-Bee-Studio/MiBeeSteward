// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package demoseed

import (
	"context"
	"testing"

	"log/slog"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/testutil"
)

func TestSeedAndWipe(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer conn.Close()

	require.True(t, IsDemoEmpty(conn), "fresh DB must be demo-empty")

	// Seed twice-safety: the caller gates on IsDemoEmpty; seeding itself must
	// succeed on an empty DB and make it non-empty.
	require.NoError(t, Seed(context.Background(), conn, slog.Default()))
	require.False(t, IsDemoEmpty(conn))

	counts := func(q string) int {
		var n int
		require.NoError(t, conn.QueryRow(q).Scan(&n))
		return n
	}
	require.Equal(t, 2, counts(`SELECT COUNT(*) FROM networks WHERE name LIKE 'demo-%'`))
	require.Equal(t, len(demoDevices), counts(`SELECT COUNT(*) FROM devices WHERE device_uuid LIKE 'demo-uuid-%'`))
	require.Positive(t, counts(`SELECT COUNT(*) FROM change_log`))
	require.Equal(t, 3, counts(`SELECT COUNT(*) FROM probe_targets WHERE name LIKE 'demo-%'`))
	require.Equal(t, 3*30, counts(`SELECT COUNT(*) FROM probe_results`))
	require.Positive(t, counts(`SELECT COUNT(*) FROM topology_edges`))
	// All device IPs are RFC 5737 documentation ranges — demo data can never
	// collide with a real network.
	require.Equal(t, len(demoDevices), counts(`SELECT COUNT(*) FROM devices
		WHERE (ip_address LIKE '198.51.100.%' OR ip_address LIKE '203.0.113.%') AND device_uuid LIKE 'demo-uuid-%'`))

	// Wipe clears every demo-marked row.
	require.NoError(t, Wipe(context.Background(), conn))
	require.True(t, IsDemoEmpty(conn), "wipe must return the DB to demo-empty")
	require.Equal(t, 0, counts(`SELECT COUNT(*) FROM change_log WHERE network_id IS NOT NULL AND network_id IN (SELECT id FROM networks)`))
	require.Equal(t, 0, counts(`SELECT COUNT(*) FROM probe_targets`))
	require.Equal(t, 0, counts(`SELECT COUNT(*) FROM probe_results`))
}

func TestSeedDoesNotTouchNonEmptyDB(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Exec(`INSERT INTO devices (name, ip_address, device_uuid) VALUES ('real', '10.0.0.1', 'real-uuid')`)
	require.NoError(t, err)
	require.False(t, IsDemoEmpty(conn), "a DB with real devices must never be seeded")
}
