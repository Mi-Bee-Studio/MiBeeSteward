// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
)

// TestDeviceService_GetStats_ScopeMatrix pins the stats boundary contract at
// the service level: global scope, per-network global, restricted scope with
// granted/ungranted networks, and restricted-without-pick.
func TestDeviceService_GetStats_ScopeMatrix(t *testing.T) {
	repo, conn, queries, ctx := setupDeviceRepoGap(t)

	netA := seedGapNetwork(t, ctx, queries, "stats-a")
	netB := seedGapNetwork(t, ctx, queries, "stats-b")
	seedRepoDevice(t, ctx, conn, "st-1", "10.140.0.1", "online", "camera", netA)
	seedRepoDevice(t, ctx, conn, "st-2", "10.140.0.2", "offline", "camera", netA)
	seedRepoDevice(t, ctx, conn, "st-3", "10.141.0.1", "online", "switch", netB)

	svc := NewDeviceService(repo, nil)
	netAptr, netBptr := netA, netB

	count := func(s *domain.DeviceStatsResponse) int {
		var n int
		for _, v := range s.ByStatus {
			n += int(v)
		}
		return n
	}

	// Global scope, no network filter: all devices.
	stats, err := svc.GetStats(ctx, nil, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, 3, count(stats))

	// Global scope with a network filter.
	stats, err = svc.GetStats(ctx, &netAptr, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Equal(t, 2, count(stats))

	// Restricted scope granted on A only.
	scopeA := domain.Scope{Global: false, NetworkIDs: []int64{netA}}
	stats, err = svc.GetStats(ctx, nil, scopeA)
	require.NoError(t, err)
	require.Equal(t, 2, count(stats))

	// Restricted scope + in-scope network pick.
	stats, err = svc.GetStats(ctx, &netAptr, scopeA)
	require.NoError(t, err)
	require.Equal(t, 2, count(stats))

	// Restricted scope + OUT-of-scope network pick → zero counts (no leak).
	stats, err = svc.GetStats(ctx, &netBptr, scopeA)
	require.NoError(t, err)
	require.Equal(t, 0, count(stats))
}

// TestDeviceRepo_MoreSurfaces: UpdateScanAttributes round-trip + the unscoped
// Count surfaces (CountByStatus/CountByType + List/Count with a status filter).
func TestDeviceRepo_MoreSurfaces(t *testing.T) {
	repo, conn, queries, ctx := setupDeviceRepoGap(t)
	netA := seedGapNetwork(t, ctx, queries, "more-a")
	seedRepoDevice(t, ctx, conn, "m-1", "10.170.0.1", "online", "camera", netA)

	res, err := conn.ExecContext(ctx, `INSERT INTO devices (device_uuid, name, type, ip_address, status)
		VALUES ('uuid-attrs-host', 'attrs-host', 'server', '10.170.0.2', 'online')`)
	require.NoError(t, err)
	var devID int64
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT id FROM devices WHERE device_uuid='uuid-attrs-host'`).Scan(&devID))
	_ = res
	require.NoError(t, err)
	require.NoError(t, repo.UpdateScanAttributes(ctx, devID, domain.ScanAttributes{
		Vendor: "acme", OS: "linux", Hostname: "attrs.lan",
	}))

	var vendor, osName string
	require.NoError(t, conn.QueryRow(
		`SELECT scan_vendor, scan_os FROM devices WHERE id=?`, devID).Scan(&vendor, &osName))
	require.Equal(t, "acme", vendor)
	require.Equal(t, "linux", osName)

	byStatus, err := repo.CountByStatus(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, byStatus)
	byType, err := repo.CountByType(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, byType)

	list, err := repo.List(ctx, domain.DeviceFilter{Status: "online", Limit: 10})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(list), 2)
	n, err := repo.Count(ctx, domain.DeviceFilter{Status: "online"})
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
}
