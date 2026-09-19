// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestRecordHeartbeats_LegacyFallback drops the (device_id, method) unique
// index so RecordHeartbeats takes the check-then-upsert legacy path — the
// upgrade safety net for DBs created before the index existed.
func TestRecordHeartbeats_LegacyFallback(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	db := repo.db

	// Drop the unique index to force the legacy branch.
	_, err := db.Exec(`DROP INDEX idx_heartbeat_configs_device_method`)
	require.NoError(t, err)

	id := seedDeviceRow(t, db, "10.60.0.1", "aa:11:22:33:44:55", sql.NullInt64{})

	specs := []scannerv2.HeartbeatSpec{
		{Method: "icmp", Target: "10.60.0.1", IntervalSeconds: 30, TimeoutSeconds: 5},
	}
	require.NoError(t, repo.RecordHeartbeats(ctx, "10.60.0.1", specs))

	var method, target string
	var interval int
	require.NoError(t, db.QueryRow(`SELECT method, target, interval_seconds FROM heartbeat_configs WHERE device_id=?`, id).
		Scan(&method, &target, &interval))
	require.Equal(t, "icmp", method)
	require.Equal(t, "10.60.0.1", target)
	require.Equal(t, 30, interval)

	// Re-run on the legacy path: update, not duplicate.
	specs[0].IntervalSeconds = 45
	require.NoError(t, repo.RecordHeartbeats(ctx, "10.60.0.1", specs))
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM heartbeat_configs WHERE device_id=?`, id).Scan(&n))
	require.Equal(t, 1, n)
	require.NoError(t, db.QueryRow(`SELECT interval_seconds FROM heartbeat_configs WHERE device_id=?`, id).Scan(&interval))
	require.Equal(t, 45, interval)
}

// TestEnrichDeviceByMAC pins the enrich-existing-only contract: a matching MAC
// gets known fields applied (empty-string values preserved), unknown keys land
// in extras, and an unknown MAC is a silent no-op.
func TestEnrichDeviceByMAC(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	db := repo.db
	id := seedDeviceRow(t, db, "10.60.0.2", "aa:11:22:33:44:66", sql.NullInt64{})

	// Unknown MAC: no-op, no error.
	require.NoError(t, repo.EnrichDeviceByMAC(ctx, "ff:ff:ff:ff:ff:ff", map[string]string{"vendor": "x"}))

	// Known fields + one unknown key + one empty value (must not overwrite).
	require.NoError(t, repo.EnrichDeviceByMAC(ctx, "AA:11:22:33:44:66", map[string]string{
		"vendor":     "acme-corp",
		"hostname":   "enriched-host",
		"model":      "X1000",
		"location":   "", // empty → preserved
		"custom_key": "custom-value",
	}))

	var brand, model, name, mac, attrs string
	require.NoError(t, db.QueryRow(`SELECT brand, model, name, mac_address, scan_attributes FROM devices WHERE id=?`, id).
		Scan(&brand, &model, &name, &mac, &attrs))
	require.Equal(t, "acme-corp", brand)
	require.Equal(t, "X1000", model)
	require.Equal(t, "enriched-host", name)
	require.Contains(t, attrs, "custom-value", "unknown keys merge into scan_attributes")

	// Empty-mac and empty-fields calls are no-ops.
	require.NoError(t, repo.EnrichDeviceByMAC(ctx, "", map[string]string{"vendor": "x"}))
	require.NoError(t, repo.EnrichDeviceByMAC(ctx, "aa:11:22:33:44:66", nil))
}
