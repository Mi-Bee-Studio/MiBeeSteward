// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDeviceDelete_DetachesBoundProbeTargets pins the deletion hook (#606):
// every bound probe target is unbound; policy-generated (auto) targets are
// disabled with their origin, manual ones keep running free.
func TestDeviceDelete_DetachesBoundProbeTargets(t *testing.T) {
	svc, db := setupDeviceService(t)
	ctx := context.Background()

	created := createTestDevice(t, svc, "detach-me", "10.0.0.9", "server")
	seed := func(name, source string) {
		_, err := db.ExecContext(ctx,
			`INSERT INTO probe_targets (name, module, target, device_id, source, enabled)
			 VALUES (?, 'http', 'http://10.0.0.9/', ?, ?, 1)`, name, created.ID, source)
		require.NoError(t, err)
	}
	seed("manual-bound", "manual")
	seed("auto-bound", "auto")

	require.NoError(t, svc.Delete(ctx, created.ID))

	rows, err := db.QueryContext(ctx,
		`SELECT name, device_id, source, enabled FROM probe_targets ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()
	got := map[string]struct {
		deviceID *int64
		enabled  int
	}{}
	for rows.Next() {
		var name, source string
		var deviceID *int64
		var enabled int
		require.NoError(t, rows.Scan(&name, &deviceID, &source, &enabled))
		got[name] = struct {
			deviceID *int64
			enabled  int
		}{deviceID, enabled}
	}
	require.Len(t, got, 2)
	require.Nil(t, got["manual-bound"].deviceID)
	require.Equal(t, 1, got["manual-bound"].enabled, "manual target keeps running unbound")
	require.Nil(t, got["auto-bound"].deviceID)
	require.Equal(t, 0, got["auto-bound"].enabled, "auto target dies with its origin device")
}
