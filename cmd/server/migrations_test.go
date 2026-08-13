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
