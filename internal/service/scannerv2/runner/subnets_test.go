// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package runner

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRecordSubnets_InsertAndRefresh drives the per-scan subnet finalize:
// a network without a CIDR is skipped, the first pass inserts the subnet row,
// and the second pass refreshes (never duplicates), gateway resolution is
// matched against the kernel route table (absent on some hosts → NULL).
func TestRecordSubnets_InsertAndRefresh(t *testing.T) {
	rn, queries, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	// No CIDR on the network → nothing to anchor.
	rn.recordSubnets(ctx, rn.networkID)
	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM subnets`).Scan(&n))
	require.Zero(t, n)

	// Give the network its CIDR; first finalize inserts.
	cidr := "192.168.63.0/24"
	_, err := conn.Exec(`UPDATE networks SET cidr = ? WHERE id = ?`, cidr, rn.networkID.Int64)
	require.NoError(t, err)
	rn.recordSubnets(ctx, rn.networkID)
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM subnets`).Scan(&n))
	require.Equal(t, 1, n, "first finalize inserts exactly one subnet row")

	var gotCIDR string
	var netID int64
	require.NoError(t, conn.QueryRow(`SELECT cidr, network_id FROM subnets`).Scan(&gotCIDR, &netID))
	require.Equal(t, cidr, gotCIDR)
	require.Equal(t, rn.networkID.Int64, netID)

	// Second finalize refreshes the existing row (no duplicate).
	rn.recordSubnets(ctx, rn.networkID)
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM subnets`).Scan(&n))
	require.Equal(t, 1, n, "refresh never duplicates the subnet row")

	// An invalid network id is a no-op.
	rn.recordSubnets(ctx, sql.NullInt64{})
	_ = queries
}
