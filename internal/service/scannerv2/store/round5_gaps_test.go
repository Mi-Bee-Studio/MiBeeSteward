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
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
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

// TestRecordDevice_IdentityPaths pins the store's enrich-only identity
// resolution: a MAC-bearing ref enriches the globally-matching row, a MAC-less
// ref resolves by (ip, network_id), and a no-match is a silent no-op (device
// creation is the runner's job, not the store's).
func TestRecordDevice_IdentityPaths(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("setup db: %v", err)
	}
	t.Cleanup(func() { dbConn2Close(dbConn) })
	netID := seedGapNetRow(t, dbConn)
	id := seedDeviceRow(t, dbConn, "10.150.0.1", "aa:55:00:11:22:33", sql.NullInt64{Int64: netID, Valid: true})
	repo := NewSQLiteRepository(dbConn, Options{NetworkID: netID}, nil)
	ctx := context.Background()

	// MAC-bearing ref at a DIFFERENT IP still resolves the row globally by MAC
	// and enriches it (roaming stays one asset).
	if err := repo.RecordDevice(ctx, "10.150.0.99", scannerv2.DeviceRef{
		IP: "10.150.0.99", Brand: "acme",
		Fields: map[string]string{"mac": "aa:55:00:11:22:33", "hostname": "roamer"},
	}); err != nil {
		t.Fatalf("mac-path record: %v", err)
	}
	var brand string
	if err := dbConn.QueryRow(`SELECT brand FROM devices WHERE id=?`, id).Scan(&brand); err != nil {
		t.Fatalf("brand read: %v", err)
	}
	if brand != "acme" {
		t.Fatalf("mac-resolved row must be enriched, brand=%q", brand)
	}

	// MAC-less ref resolves by (ip, network_id).
	if err := repo.RecordDevice(ctx, "10.150.0.1", scannerv2.DeviceRef{
		IP: "10.150.0.1", Model: "X1",
	}); err != nil {
		t.Fatalf("ip-path record: %v", err)
	}
	var model string
	if err := dbConn.QueryRow(`SELECT model FROM devices WHERE id=?`, id).Scan(&model); err != nil {
		t.Fatalf("model read: %v", err)
	}
	if model != "X1" {
		t.Fatalf("ip-resolved row must be enriched, model=%q", model)
	}

	// No match anywhere → enrich-only no-op (no row created).
	before := countGapRows(t, dbConn)
	if err := repo.RecordDevice(ctx, "10.159.9.9", scannerv2.DeviceRef{
		IP: "10.159.9.9", Brand: "ghost",
	}); err != nil {
		t.Fatalf("no-match record: %v", err)
	}
	if after := countGapRows(t, dbConn); after != before {
		t.Fatalf("enrich-only store must not create rows: %d -> %d", before, after)
	}
}

func dbConn2Close(db *sql.DB) { _ = db.Close() }

func seedGapNetRow(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO networks (name) VALUES ('id-net')`)
	if err != nil {
		t.Fatalf("seed network: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func countGapRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestIdentityNetworkClause pins the per-call network scoping fragment.
func TestIdentityNetworkClause(t *testing.T) {
	clause, args := identityNetworkClause(sql.NullInt64{Int64: 7, Valid: true})
	if clause != "network_id = ?" || len(args) != 1 || args[0].(int64) != 7 {
		t.Fatalf("valid network: %q %v", clause, args)
	}
	clause, args = identityNetworkClause(sql.NullInt64{})
	if clause != "network_id IS NULL" || args != nil {
		t.Fatalf("invalid network: %q %v", clause, args)
	}
}
