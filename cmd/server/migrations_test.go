// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
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
