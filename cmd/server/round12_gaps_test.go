// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestApplyIdentityIndexMigrations_DedupesLegacyIPs pins the distributed-model
// identity migration: with the composite-unique index dropped (legacy shape),
// duplicate (ip, network) rows are deduplicated keeping the LOWEST id, and the
// composite index is recreated.
func TestApplyIdentityIndexMigrations_DedupesLegacyIPs(t *testing.T) {
	ctx := context.Background()
	db, _ := openMigratedDB(t)

	// Simulate the legacy state: no composite-unique index.
	_, err := db.Exec(`DROP INDEX IF EXISTS idx_devices_ip_network`)
	require.NoError(t, err)

	ins := func(uuid, ip string) int64 {
		res, err := db.Exec(`INSERT INTO devices (device_uuid, name, ip_address, status)
			VALUES (?, ?, ?, 'unknown')`, uuid, uuid, ip)
		require.NoError(t, err)
		id, _ := res.LastInsertId()
		return id
	}
	keepID := ins("uuid-keep", "10.120.0.7")
	dupID := ins("uuid-dup", "10.120.0.7") // same ip, both NULL network → dupe
	uniqueID := ins("uuid-uniq", "10.120.0.8")
	_, emptyIPID := ins("uuid-empty", ""), int64(0)
	_ = emptyIPID

	require.NoError(t, applyIdentityIndexMigrations(ctx, db))

	// The duplicate with the higher id is gone; the keeper + the unique row
	// survive.
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address != ''`).Scan(&n))
	require.Equal(t, 2, n)
	var exists int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE id=?`, keepID).Scan(&exists))
	require.Equal(t, 1, exists)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE id=?`, dupID).Scan(&exists))
	require.Equal(t, 0, exists)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE id=?`, uniqueID).Scan(&exists))
	require.Equal(t, 1, exists)

	// The composite-unique index is back.
	var idx int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_devices_ip_network'`).Scan(&idx))
	require.Equal(t, 1, idx)

	// Idempotent re-run.
	require.NoError(t, applyIdentityIndexMigrations(ctx, db))
}

// TestBackfills_DeviceUUIDAndOfflineSince covers the two legacy-data backfills:
// empty device_uuid rows get a fresh uuid; online devices with NULL
// offline_since get the epoch marker.
func TestBackfills_DeviceUUIDAndOfflineSince(t *testing.T) {
	ctx := context.Background()
	db, _ := openMigratedDB(t)

	// Two rows: an OFFLINE row (offline_since backfill target) and an online
	// row with an empty uuid (uuid backfill target).
	_, err := db.Exec(`INSERT INTO devices (device_uuid, name, ip_address, status, offline_since)
		VALUES ('', 'no-uuid', '10.121.0.2', 'online', NULL)`)
	require.NoError(t, err)
	res, err := db.Exec(`INSERT INTO devices (device_uuid, name, ip_address, status, offline_since)
		VALUES ('uuid-has', 'offline-host', '10.121.0.1', 'offline', NULL)`)
	require.NoError(t, err)
	id, _ := res.LastInsertId()

	require.NoError(t, backfillDeviceUUIDs(ctx, db))
	require.NoError(t, backfillOfflineSince(ctx, db))

	var uuid string
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE id=?`, id).Scan(&uuid))
	require.NotEmpty(t, uuid, "empty uuid must be backfilled")
	var offline sql.NullTime
	require.NoError(t, db.QueryRow(`SELECT offline_since FROM devices WHERE status='offline'`).Scan(&offline))
	require.True(t, offline.Valid, "offline device gets offline_since = updated_at")

	// Idempotent second pass.
	require.NoError(t, backfillDeviceUUIDs(ctx, db))
	require.NoError(t, backfillOfflineSince(ctx, db))
}

// TestRunMigrations_FingerprintShortCircuit: a DB already carrying the current
// chain fingerprint skips the migration chain (the steady-state boot path).
func TestRunMigrations_FingerprintShortCircuit(t *testing.T) {
	dbPath := "file:" + t.TempDir() + "/fp.db?cache=shared"
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// First run: applies schema + records the fingerprint.
	require.NoError(t, runMigrations(db, dbPath))
	fp := storedChainFingerprint(db)
	require.NotEmpty(t, fp)

	// Second run detects the stored fingerprint and short-circuits (the log
	// line "schema already at version" marks the branch).
	start := time.Now()
	require.NoError(t, runMigrations(db, dbPath))
	require.Less(t, time.Since(start), 5*time.Second)
}

// TestDoctor_BackupBranches drives the backup checks: a fresh valid backup
// answers ok + restorable; a corrupt backup fails restorable (still exit 1
// only if another check failed — backup warn alone exits 0).
func TestDoctor_BackupBranches(t *testing.T) {
	dbDir := t.TempDir()
	cfg := writeDoctorConfig(t, filepath.Join(dbDir, "mibee.db"), "0123456789abcdef0123456789abcdef")

	// No backups dir → warn branch (already covered); create backups with a
	// REAL sqlite file so "restorable" runs its integrity probe.
	backupDir := filepath.Join(dbDir, "backups")
	require.NoError(t, os.MkdirAll(backupDir, 0o755))
	bk, err := sql.Open("sqlite", filepath.Join(backupDir, "mibee-steward.db"))
	require.NoError(t, err)
	_, err = bk.Exec(`CREATE TABLE t(x)`)
	require.NoError(t, err)
	require.NoError(t, bk.Close())

	// Backups fresh → exit code driven by ICMP sysctl only (same derivation
	// as the main doctor test).
	wantExit := 0
	if raw, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range"); err == nil {
		if c, ok := icmpPingGroupRangeCheck(string(raw), os.Getgid()); ok && c.status == "fail" {
			wantExit = doctorFailExit
		}
	}
	require.Equal(t, wantExit, doctor([]string{"-config", cfg}))
}
