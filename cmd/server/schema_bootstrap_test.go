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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fresh-database policy: a new file is created from the embedded schema
// and stamped, and re-running on the stamped database is a no-op.
func TestRunMigrations_FreshStampAndNoOp(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mibee.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	require.NoError(t, runMigrations(db, dbPath))
	var v int
	require.NoError(t, db.QueryRow(`PRAGMA user_version`).Scan(&v))
	require.Equal(t, SchemaVersion, v)
	var users int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='users'`).Scan(&users))
	require.Equal(t, 1, users)

	require.NoError(t, runMigrations(db, dbPath))
}

// A database carrying tables but no version stamp (or a foreign one) is
// rejected with instructions instead of migrated.
func TestRunMigrations_RejectsLegacyDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY)`)
	require.NoError(t, err)

	err = runMigrations(db, dbPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no longer upgrades older databases")
}
