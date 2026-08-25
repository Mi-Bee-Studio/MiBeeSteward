// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"fmt"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/metrics"
	"mibee-steward/internal/testutil"
)

// TestUpdateDeviceMetrics_TracksDBChanges pins the refresh semantics the 60s
// refresher loop relies on (#333): a second call after devices are removed /
// added must move the gauges to the new DB state — including label
// combinations dropping to zero (a status with no devices left disappears
// entirely via the Reset, not a stale nonzero reading).
func TestUpdateDeviceMetrics_TracksDBChanges(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	seed := func(n int, status string) {
		for i := 0; i < n; i++ {
			_, err := conn.ExecContext(ctx,
				`INSERT INTO devices (device_uuid, name, ip_address, mac_address, type, status) VALUES (?, ?, ?, '', 'other', ?)`,
				fmt.Sprintf("uuid-%s-%d", status, i), fmt.Sprintf("dev-%s-%d", status, i),
				fmt.Sprintf("10.0.%d.%d", i, int(status[0])), status)
			require.NoError(t, err)
		}
	}

	seed(5, "online")
	seed(3, "offline")
	UpdateDeviceMetrics(ctx, conn)
	require.Equal(t, 5.0, promtestutil.ToFloat64(metrics.MibeeDevicesTotal.WithLabelValues("online", "")))
	require.Equal(t, 3.0, promtestutil.ToFloat64(metrics.MibeeDevicesTotal.WithLabelValues("offline", "")))

	// The #333 shape: a bulk SQL cleanup (1023 phantom rows) between refreshes.
	_, err = conn.ExecContext(ctx, `DELETE FROM devices WHERE status = 'online'`)
	require.NoError(t, err)

	UpdateDeviceMetrics(ctx, conn)
	require.Equal(t, 0.0, promtestutil.ToFloat64(metrics.MibeeDevicesTotal.WithLabelValues("online", "")))
	require.Equal(t, 3.0, promtestutil.ToFloat64(metrics.MibeeDevicesTotal.WithLabelValues("offline", "")))
}
