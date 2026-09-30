// SPDX-License-Identifier: AGPL-3.0-or-later.
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text.

package dbopen

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// txlockFixture opens two pools over a seeded one-row WAL table. Pool A runs
// the read-then-write transaction, pool B plays the concurrent writer.
func txlockFixture(t *testing.T, immediate bool) (a, b *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "txlock.db")
	open := func() *sql.DB {
		if immediate {
			db, err := OpenTxLock(path, "immediate",
				"journal_mode=WAL", "busy_timeout=2000")
			require.NoError(t, err)
			return db
		}
		db, err := Open(path, "journal_mode=WAL", "busy_timeout=2000")
		require.NoError(t, err)
		return db
	}
	a, b = open(), open()
	t.Cleanup(func() { a.Close(); b.Close() })

	_, err := a.Exec(`CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT)`)
	require.NoError(t, err)
	_, err = a.Exec(`INSERT INTO t (k, v) VALUES (1, 'a')`)
	require.NoError(t, err)
	return a, b
}

// TestTxLock_DeferredHitsBusySnapshot pins the failure mode the agent saw in
// the field (2026-09-29: recurring "enrich device failed / database is locked
// (517)" during concurrent scans): under the default DEFERRED transaction,
// when another writer commits between this transaction's read and its write,
// the write-lock upgrade fails with SQLITE_BUSY_SNAPSHOT immediately —
// busy_timeout does not (cannot) retry a stale-snapshot upgrade.
func TestTxLock_DeferredHitsBusySnapshot(t *testing.T) {
	a, b := txlockFixture(t, false)
	ctx := context.Background()

	tx, err := a.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback() //nolint:errcheck

	var v string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT v FROM t WHERE k=1`).Scan(&v))

	// The interferer commits cleanly while tx holds only a read snapshot.
	_, err = b.Exec(`UPDATE t SET v='b' WHERE k=1`)
	require.NoError(t, err)

	_, err = tx.ExecContext(ctx, `UPDATE t SET v='c' WHERE k=1`)
	require.Error(t, err, "deferred write after a concurrent commit must fail (SQLITE_BUSY_SNAPSHOT)")
}

// TestTxLock_ImmediateSurvivesConcurrentWriter is the fix's other half: with
// _txlock=immediate the transaction holds the write lock from BEGIN, so the
// stale-snapshot upgrade simply cannot occur — the read-then-write sequence
// succeeds, and a writer that started mid-transaction queues behind it (via
// busy_timeout) and lands after the commit.
func TestTxLock_ImmediateSurvivesConcurrentWriter(t *testing.T) {
	a, b := txlockFixture(t, true)
	ctx := context.Background()

	tx, err := a.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback() //nolint:errcheck

	var v string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT v FROM t WHERE k=1`).Scan(&v))

	_, err = tx.ExecContext(ctx, `UPDATE t SET v='c' WHERE k=1`)
	require.NoError(t, err, "immediate transaction's write must not fail with SQLITE_BUSY_SNAPSHOT")
	require.NoError(t, tx.Commit())

	// The concurrent writer lands after the commit instead of poisoning it.
	_, err = b.Exec(`UPDATE t SET v='b' WHERE k=1`)
	require.NoError(t, err)
	var got string
	require.NoError(t, a.QueryRow(`SELECT v FROM t WHERE k=1`).Scan(&got))
	require.Equal(t, "b", got)
}
