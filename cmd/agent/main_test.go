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
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestOpenAgentDB_RejectsLegacyDB pins the fresh-database policy: a mini-DB
// created by an older agent build is refused at startup instead of upgraded,
// and the error names the file so an operator knows what to move aside. A
// brand-new path provisions normally and survives a reopen.
func TestOpenAgentDB_RejectsLegacyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/legacy.db"

	legacy, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = legacy.Exec(`CREATE TABLE devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	require.NoError(t, legacy.Close())

	_, err = openAgentDB(dbPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "older build")
	require.Contains(t, err.Error(), dbPath)

	conn, err := openAgentDB(dir + "/fresh.db")
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	conn2, err := openAgentDB(dir + "/fresh.db")
	require.NoError(t, err)
	var v int
	require.NoError(t, conn2.QueryRow(`PRAGMA user_version`).Scan(&v))
	require.Equal(t, agentSchemaVersion, v)
	require.NoError(t, conn2.Close())
}
