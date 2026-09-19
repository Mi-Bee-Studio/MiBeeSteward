// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestTOTPService_DeadDB_Tails sweeps the storage-error wraps: every method's
// first query fails on a dead handle, pinning the error-tail of Setup /
// Enable / Verify / GetStatus / Disable.
func TestTOTPService_DeadDB_Tails(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	svc := NewTOTPService(conn, nil)
	ctx := context.Background()

	_, err = svc.Setup(ctx, 1, "alice")
	require.ErrorContains(t, err, "failed to store TOTP secret")

	err = svc.Enable(ctx, 1, "123456")
	require.ErrorContains(t, err, "failed to get TOTP record")

	err = svc.Verify(ctx, 1, "123456")
	require.ErrorContains(t, err, "failed to get TOTP record")

	_, err = svc.GetStatus(ctx, 1)
	require.Error(t, err)

	err = svc.Disable(ctx, 1, "pass")
	require.Error(t, err)
}

// TestDashboardService_DataSourceTails pins the data-source resolution
// branches: the default (non-prometheus) arm errors when no URL is set, and
// a malformed URL fails the proxy request at construction.
func TestDashboardService_DataSourceTails(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	weird := &config.Config{}
	weird.Dashboard.DataSourceType = "graphite" // default arm
	svc := NewDashboardService(conn, weird)

	_, err = svc.Query(context.Background(), "up", "")
	require.ErrorContains(t, err, "prometheus URL not configured")

	// The service snapshots the URL at construction — rebuild after changing it.
	weird.Dashboard.PrometheusURL = "http://[::bad-url"
	svc = NewDashboardService(conn, weird)
	_, err = svc.Query(context.Background(), "up", "")
	require.ErrorContains(t, err, "failed to create request")

	_, err = svc.QueryRange(context.Background(), "up", "1", "2", "15")
	require.ErrorContains(t, err, "failed to create request")
}

// TestDashboardService_Overview_DeadDB pins the Overview pipeline's first
// error wrap (scan-status query) on a dead handle.
func TestDashboardService_Overview_DeadDB(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	svc := NewDashboardService(conn, &config.Config{})
	_, err = svc.Overview(context.Background(), domain.Scope{Global: true})
	require.ErrorContains(t, err, "overview:")
}
