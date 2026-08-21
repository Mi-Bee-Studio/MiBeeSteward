// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, copy, modify, and redistribute it
// under those terms; see LICENSE for the full text. A commercial license is
// available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package dbopen

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestOpen_AppliesPragmasToEveryConnection is the regression test for #252:
// pragmas passed through the DSN must reach EVERY pool connection, not just
// the first one. It forces the pool onto two distinct connections (a held
// transaction pins one, a second query needs another) and reads the pragma
// value back on both. The old Exec-after-Open style fails this on connection
// two with busy_timeout=0.
func TestOpen_AppliesPragmasToEveryConnection(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "busy.db"),
		"busy_timeout=5000", "journal_mode=WAL")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(2)

	tx, err := db.Begin()
	require.NoError(t, err)
	t.Cleanup(func() { tx.Rollback() })

	var txTimeout, poolTimeout int
	require.NoError(t, tx.QueryRow("PRAGMA busy_timeout").Scan(&txTimeout))
	require.NoError(t, db.QueryRow("PRAGMA busy_timeout").Scan(&poolTimeout))
	require.Equal(t, 5000, txTimeout, "connection held by the transaction missed the pragma")
	require.Equal(t, 5000, poolTimeout, "second pool connection missed the pragma")
}

// TestOpen_RejectsBadPragmas pins the DSN builder's validation: pragmas that
// would corrupt the query string are rejected up front, not silently mangled.
func TestOpen_RejectsBadPragmas(t *testing.T) {
	_, err := DSN(filepath.Join(t.TempDir(), "x.db"), "busy_timeout=5000)")
	require.Error(t, err)
	_, err = DSN(filepath.Join(t.TempDir(), "x.db"), "novalue")
	require.Error(t, err)
	_, err = DSN("")
	require.Error(t, err)
}

// TestDSN_EscapesPath guards the URI escaping of path characters that would
// otherwise be parsed as query-string structure.
func TestDSN_EscapesPath(t *testing.T) {
	dsn, err := DSN("/tmp/we?ird#name.db", "busy_timeout=1000")
	require.NoError(t, err)
	require.Equal(t, "file:/tmp/we%3Fird%23name.db?_pragma=busy_timeout(1000)", dsn)

	// The escaped DSN must round-trip: open it and confirm the pragma landed.
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	var timeout int
	require.NoError(t, db.QueryRow("PRAGMA busy_timeout").Scan(&timeout))
	require.Equal(t, 1000, timeout)
}
