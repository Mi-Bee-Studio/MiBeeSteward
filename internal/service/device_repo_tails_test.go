// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestDeviceRepository_DeadDB_FirstErrorTails pins the first-error wraps of
// the CRUD paths on a dead handle (create insert, MAC lookup, list, count).
func TestDeviceRepository_DeadDB_FirstErrorTails(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	repo := NewDeviceRepository(conn)
	ctx := context.Background()

	_, err = repo.Create(ctx, domain.CreateDeviceRequest{IPAddress: "10.0.0.1", Name: "x", Type: "other"})
	require.Error(t, err)

	_, _, err = repo.GetByMAC(ctx, "aa:bb:cc:dd:ee:ff")
	require.Error(t, err)

	_, err = repo.List(ctx, domain.DeviceFilter{Limit: 10})
	require.Error(t, err)

	_, err = repo.Count(ctx, domain.DeviceFilter{})
	require.Error(t, err)

	err = repo.UpdateUserAttributes(ctx, 1, domain.UserAttributes{"k": "v"})
	require.Error(t, err)
}
