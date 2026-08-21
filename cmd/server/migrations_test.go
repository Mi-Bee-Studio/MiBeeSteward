// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestRunMigrations_Idempotent verifies that runMigrations can be called twice
// on the same database without errors. This is the critical regression guard:
// the migration suite uses CREATE TABLE IF NOT EXISTS + ALTER TABLE guarded by
// "duplicate column" checks + table rebuilds, all of which MUST be safe to
// re-run (the server calls runMigrations on every startup). (#171)
func TestRunMigrations_Idempotent(t *testing.T) {
	// Use a temp file DB (runMigrations does VACUUM INTO which needs a file path).
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// First run: creates all tables + runs all ALTER/backfill migrations.
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	require.NoError(t, runMigrations(db, dbPath), "first runMigrations must succeed")

	// Verify core tables exist.
	var count int
	err = db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('devices','networks','scan_results','users','audit_logs')`).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 5, count, "core tables must exist after migration")

	// Second run: must be idempotent — no errors on re-application.
	require.NoError(t, runMigrations(db, dbPath), "second runMigrations must succeed (idempotent)")

	// Verify the devices table has the expected columns (proves ALTER migrations ran).
	_, err = db.Exec(`SELECT scan_attributes, device_uuid, offline_since FROM devices LIMIT 0`)
	require.NoError(t, err, "devices table must have scan_attributes, device_uuid, offline_since columns")
}

// TestRunMigrations_FileNotExists verifies runMigrations works on a fresh DB
// (the os.Stat check for backup should gracefully skip when the file doesn't exist yet).
func TestRunMigrations_FreshDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "fresh.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close(); os.Remove(dbPath) })

	// On a fresh DB, os.Stat fails → backup skipped → schema applied directly.
	require.NoError(t, runMigrations(db, dbPath))

	// Verify users table exists (seedAdminUser depends on it).
	_, err = db.Exec(`SELECT id, username FROM users LIMIT 0`)
	require.NoError(t, err, "users table must exist after fresh migration")
}

// TestRunMigrations_UsersRoleCheckWidened verifies that after runMigrations the
// users.role CHECK accepts all four RBAC roles (#138). A fresh DB gets the wide
// CHECK straight from schema.sql; an upgraded DB gets it from
// extendUsersRoleCheck. Either way, all four roles must be insertable.
func TestRunMigrations_UsersRoleCheckWidened(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "role.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	require.NoError(t, runMigrations(db, dbPath))

	for _, role := range []string{"admin", "operator", "viewer", "user"} {
		_, err := db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, 'x', ?)`,
			"u_"+role, "u_"+role+"@invalid", role)
		require.NoError(t, err, "role %q must be accepted after migration", role)
	}
	// An unknown role is still rejected (CHECK enforced, not dropped).
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('u_bogus', 'u_bogus@invalid', 'x', 'superuser')`)
	require.Error(t, err, "an unknown role must still be rejected by the CHECK")
}

// TestExtendUsersRoleCheck_RebuildsFromNarrowCheck verifies the migration
// rebuilds an OLD-shape users table (narrow admin/user CHECK) to accept
// operator/viewer, preserves existing rows (id + role), and is idempotent. This
// exercises the rebuild path directly — a fresh install already gets the wide
// CHECK from schema.sql and short-circuits via the probe.
func TestExtendUsersRoleCheck_RebuildsFromNarrowCheck(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "narrow.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Create the OLD-shape users table (narrow CHECK, pre-#138).
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		failed_login_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until TIMESTAMP,
		password_changed_at DATETIME,
		must_change_password BOOLEAN NOT NULL DEFAULT 0
	)`)
	require.NoError(t, err)

	// Seed a real user; confirm the narrow CHECK rejects 'operator'.
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('admin1', 'a@x', 'h', 'admin')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('op1', 'o@x', 'h', 'operator')`)
	require.Error(t, err, "narrow CHECK must reject 'operator' before migration")

	// Run the migration.
	require.NoError(t, extendUsersRoleCheck(ctx, db))

	// The seed row survived the rebuild (id + role preserved).
	var id int64
	var role string
	require.NoError(t, db.QueryRow(`SELECT id, role FROM users WHERE username = 'admin1'`).Scan(&id, &role))
	require.Equal(t, "admin", role)
	require.EqualValues(t, 1, id, "id must be preserved across the rebuild")

	// 'operator' is now insertable (the widened CHECK accepts it).
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('op1', 'o@x', 'h', 'operator')`)
	require.NoError(t, err, "widened CHECK must accept 'operator'")

	// 'viewer' too.
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('v1', 'v@x', 'h', 'viewer')`)
	require.NoError(t, err, "widened CHECK must accept 'viewer'")

	// Idempotent: re-running is a no-op (the probe short-circuits).
	require.NoError(t, extendUsersRoleCheck(ctx, db))
}

// TestBackfillScanTaskNetworks verifies the #138 Phase 2c migration: an
// old-shape scan_tasks table (no network_id column) gets the column added by
// runMigrations, and existing tasks are backfilled — a single-CIDR targets
// string exactly matching a networks.cidr resolves to that network, while
// multi-CIDR/unmatched targets stay NULL (cross-network).
func TestBackfillScanTaskNetworks(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "backfill.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Old shape: scan_tasks WITHOUT network_id (pre-2c). runMigrations adds it.
	_, err = db.Exec(`CREATE TABLE scan_tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		targets TEXT NOT NULL,
		cron_expr TEXT NOT NULL DEFAULT '0 */6 * * *',
		pipeline_config TEXT NOT NULL DEFAULT '{}',
		global_labels TEXT NOT NULL DEFAULT '{}',
		timeout INTEGER NOT NULL DEFAULT 300,
		concurrent_hosts INTEGER NOT NULL DEFAULT 50,
		enabled INTEGER NOT NULL DEFAULT 1,
		last_run_at TIMESTAMP,
		next_run_at TIMESTAMP,
		last_run_status TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	// networks + three tasks: single-CIDR match, non-canonical raw match, and
	// a multi-CIDR cross-network task.
	_, err = db.Exec(`CREATE TABLE networks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		cidr TEXT,
		site TEXT,
		agent_id TEXT,
		metadata TEXT NOT NULL DEFAULT '{}',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO networks (id, name, cidr) VALUES
		(1, 'lan-1', '10.0.1.0/24'),
		(2, 'lan-2', '10.0.2.0/24')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO scan_tasks (id, name, targets) VALUES
		(1, 'task-match', '10.0.1.0/24'),
		(2, 'task-multi', '10.0.1.0/24,10.0.2.0/24'),
		(3, 'task-nomatch', '172.16.0.0/24')`)
	require.NoError(t, err)

	require.NoError(t, runMigrations(db, dbPath))

	var net1, net2, net3 sql.NullInt64
	require.NoError(t, db.QueryRow(`SELECT network_id FROM scan_tasks WHERE id = 1`).Scan(&net1))
	require.NoError(t, db.QueryRow(`SELECT network_id FROM scan_tasks WHERE id = 2`).Scan(&net2))
	require.NoError(t, db.QueryRow(`SELECT network_id FROM scan_tasks WHERE id = 3`).Scan(&net3))
	require.True(t, net1.Valid, "single-CIDR task must resolve to its network")
	require.EqualValues(t, 1, net1.Int64)
	require.False(t, net2.Valid, "multi-CIDR task stays NULL (cross-network)")
	require.False(t, net3.Valid, "unmatched CIDR stays NULL")

	// Idempotent: re-running keeps the same values.
	require.NoError(t, backfillScanTaskNetworks(ctx, db))
	require.NoError(t, db.QueryRow(`SELECT network_id FROM scan_tasks WHERE id = 1`).Scan(&net1))
	require.EqualValues(t, 1, net1.Int64)
}

// TestRunMigrations_ConvertsGoStringTimestamps verifies the #257 conversion:
// legacy Go time.String() values ("... +0000 UTC") become RFC3339 so SQLite
// date()/datetime() parse them; already-RFC3339 and CURRENT_TIMESTAMP-style
// values pass through untouched (idempotent).
func TestRunMigrations_ConvertsGoStringTimestamps(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "ts.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	require.NoError(t, runMigrations(db, dbPath))

	// Seed one legacy-format row per converted column family.
	_, err = db.Exec(`INSERT INTO devices (name, ip_address, updated_at, created_at) VALUES ('d', '10.0.0.1', '2026-07-22 18:02:15.149625246 +0000 UTC', '2026-07-22 18:02:15 +0000 UTC')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO host_services (ip, service, port, updated_at) VALUES ('10.0.0.1', 'http', 80, '2026-07-25 17:30:47.80315038 +0000 UTC')`)
	require.NoError(t, err)

	require.NoError(t, runMigrations(db, dbPath))

	var devUpdated, svcUpdated string
	require.NoError(t, db.QueryRow(`SELECT updated_at FROM devices WHERE ip_address='10.0.0.1'`).Scan(&devUpdated))
	require.NoError(t, db.QueryRow(`SELECT updated_at FROM host_services WHERE ip='10.0.0.1'`).Scan(&svcUpdated))
	require.Equal(t, "2026-07-22T18:02:15Z", devUpdated)
	require.Equal(t, "2026-07-25T17:30:47Z", svcUpdated)

	// date() now parses them (returned NULL on the legacy form).
	var dt string
	require.NoError(t, db.QueryRow(`SELECT date(updated_at) FROM host_services WHERE ip='10.0.0.1'`).Scan(&dt))
	require.Equal(t, "2026-07-25", dt)

	// Idempotent: second run leaves RFC3339 values alone.
	require.NoError(t, runMigrations(db, dbPath))
	require.NoError(t, db.QueryRow(`SELECT updated_at FROM host_services WHERE ip='10.0.0.1'`).Scan(&svcUpdated))
	require.Equal(t, "2026-07-25T17:30:47Z", svcUpdated)
}
