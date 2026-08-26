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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/testutil"

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

	// Reset the version stamp so the gated chain replays (the conversion
	// pass below is part of the migration chain; #268 skips stamped DBs).
	_, resetErr := db.Exec(`PRAGMA user_version = 0`)
	require.NoError(t, resetErr)
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

// TestConvertDashboardConfigPosition verifies the #247 migration: an old-shape
// dashboard_configs table (TEXT position, '{}' values) is rebuilt with an
// INTEGER position, rows survive, legacy values are re-assigned 1-based by id,
// and the migration is idempotent. A fresh-shape table (INTEGER position) must
// pass through untouched.
func TestConvertDashboardConfigPosition(t *testing.T) {
	ctx := context.Background()
	// File-backed DB, not testutil's :memory: — the migration opens its own
	// transaction (pool connection) and an in-memory DB is per-connection.
	tmpDir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(tmpDir, "dashpos.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Create the LEGACY shape directly: the TEXT-position table the first
	// release shipped (before schema.sql moved position to INTEGER).
	_, err = db.Exec(`CREATE TABLE dashboard_configs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL CHECK(type IN ('gauge', 'line', 'bar', 'pie')),
		data_source TEXT NOT NULL DEFAULT 'prometheus' CHECK(data_source IN ('prometheus', 'victoriametrics')),
		query TEXT NOT NULL DEFAULT '',
		refresh_interval INTEGER NOT NULL DEFAULT 30,
		position TEXT NOT NULL DEFAULT '{}',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	// Two legacy widgets, both with the unusable '{}' position.
	_, err = db.Exec(`INSERT INTO dashboard_configs (id, name, type, position) VALUES
		(1, 'legacy-a', 'gauge', '{}'),
		(2, 'legacy-b', 'line', '{}')`)
	require.NoError(t, err)

	require.NoError(t, convertDashboardConfigPosition(ctx, db))

	// Column type is now INTEGER.
	var colType string
	require.NoError(t, db.QueryRow(`SELECT type FROM pragma_table_info('dashboard_configs') WHERE name = 'position'`).Scan(&colType))
	require.Contains(t, strings.ToUpper(colType), "INT", "position must be INTEGER after migration, got %q", colType)

	// Rows survived with 1-based positions ordered by id.
	rows, err := db.Query(`SELECT id, position, typeof(position) FROM dashboard_configs ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	got := map[int64]int64{}
	for rows.Next() {
		var id, pos int64
		var kind string
		require.NoError(t, rows.Scan(&id, &pos, &kind))
		require.Equal(t, "integer", kind, "stored value must be an integer, not text")
		got[id] = pos
	}
	require.Equal(t, map[int64]int64{1: 1, 2: 2}, got)

	// Idempotent: second run is a no-op (probe sees INTEGER).
	require.NoError(t, convertDashboardConfigPosition(ctx, db))
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM dashboard_configs`).Scan(&count))
	require.Equal(t, 2, count)
}

// TestSchemaEquivalence_FreshVsMigrated (#268): a brand-new database created
// by schema.sql alone must be structurally identical to one that went through
// the full migration chain. This is the CI assertion that keeps the two
// schema sources (schema.sql for fresh installs, the chain for upgrades)
// from drifting apart: table + index DDL compared name-by-name.
func TestSchemaEquivalence_FreshVsMigrated(t *testing.T) {
	fresh, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer fresh.Close()

	// Migrated: empty file, chain runs end-to-end and stamps the version.
	migPath := filepath.Join(t.TempDir(), "mig.db")
	migrated, err := sql.Open("sqlite", migPath)
	require.NoError(t, err)
	defer migrated.Close()
	require.NoError(t, runMigrations(migrated, migPath))

	dump := func(db *sql.DB) map[string]string {
		rows, err := db.Query(`SELECT type || ':' || name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name`)
		require.NoError(t, err)
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var k, v string
			require.NoError(t, rows.Scan(&k, &v))
			// Normalize whitespace so formatting differences don't mask as drift.
			out[k] = strings.Join(strings.Fields(v), " ")
		}
		return out
	}

	freshDump, migDump := dump(fresh), dump(migrated)
	require.Equal(t, len(freshDump), len(migDump),
		"object count differs: fresh=%d migrated=%d", len(freshDump), len(migDump))
	for k, v := range freshDump {
		mv, ok := migDump[k]
		require.True(t, ok, "object %s missing from migrated DB", k)
		require.Equal(t, v, mv, "DDL drift on %s", k)
	}
}

// dumpSchema renders a DB's structure as a normalized name→DDL map — the
// comparison basis for the convergence tests below.
func dumpSchema(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT type || ':' || name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		require.NoError(t, rows.Scan(&k, &v))
		out[k] = strings.Join(strings.Fields(v), " ")
	}
	return out
}

// assertSchemaConverged compares a converged DB against the fresh-install
// reference. Tables: identical column-NAME sets (column ORDER deliberately
// not compared — a legacy DB re-adds chain columns at the table tail while
// schema.sql interleaves them mid-table; that divergence predates this test
// and is benign because every query addresses columns by name). Indexes and
// every other object: exact DDL match.
func assertSchemaConverged(t *testing.T, want, got map[string]string, wantDB, gotDB *sql.DB) {
	t.Helper()
	// Object name sets must match exactly (missing table/index = the incident
	// class this test exists to catch).
	require.ElementsMatch(t, keysOf(want), keysOf(got))
	for k, wv := range want {
		gv, ok := got[k]
		require.True(t, ok, "object %s missing from converged DB", k)
		if strings.HasPrefix(k, "table:") {
			table := strings.TrimPrefix(k, "table:")
			assertSameColumns(t, wantDB, gotDB, table)
			continue
		}
		require.Equal(t, wv, gv, "DDL drift on %s after convergence", k)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func assertSameColumns(t *testing.T, wantDB, gotDB *sql.DB, table string) {
	t.Helper()
	cols := func(db *sql.DB) []string {
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?) ORDER BY name`, table)
		require.NoError(t, err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var c string
			require.NoError(t, rows.Scan(&c))
			out = append(out, c)
		}
		return out
	}
	require.Equal(t, cols(wantDB), cols(gotDB), "column set drift on table %s", table)
}

// emulateLegacyDB strips every chain-added column it can from a fully-migrated
// DB, approximating a database last touched by an older binary (whose tables
// predate those columns). Indexes on affected tables are dropped first —
// SQLite refuses DROP COLUMN while an index references the column; the chain
// (schema.sql apply + index steps) recreates them. Columns entangled with
// CHECK constraints can't be dropped (e.g. devices.scan_attributes) and are
// skipped — the droppable majority still exercises the convergence path every
// future chain addition will take (new columns are always plain ADD COLUMNs).
func emulateLegacyDB(t *testing.T, db *sql.DB) {
	t.Helper()
	alterRe := regexp.MustCompile(`(?i)^ALTER TABLE (\w+) ADD COLUMN (\w+)`)
	dropped := 0
	for _, stmt := range append(preSchemaMigrations, columnMigrations...) {
		m := alterRe.FindStringSubmatch(stmt)
		require.NotNil(t, m, "unparseable chain statement: %q", stmt)
		table, column := m[1], m[2]
		// Drop dependent indexes first (schema.sql / chain steps recreate them).
		idxRows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name = ? AND sql IS NOT NULL`, table)
		if err == nil {
			var idxs []string
			for idxRows.Next() {
				var name string
				require.NoError(t, idxRows.Scan(&name))
				idxs = append(idxs, name)
			}
			idxRows.Close()
			for _, name := range idxs {
				_, _ = db.Exec(`DROP INDEX ` + name)
			}
		}
		if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s DROP COLUMN %s`, table, column)); err == nil {
			dropped++
		} // else: CHECK/FK-entangled column — see func comment.
	}
	require.NotZero(t, dropped, "emulation must drop at least some chain columns")
}

// TestRunMigrations_MissingChainColumnsConverge is the generic gate for the
// #328 incident class: a database whose tables lack ANY subset of chain-added
// columns (i.e. last touched by an older binary) must converge to the exact
// fresh-install schema when the chain runs. Any future chain addition whose
// ALTER is unreachable from legacy shapes — wrong placement relative to the
// schema.sql apply, or a schema.sql index referencing the new column before
// its ALTER runs — fails here at PR time instead of in the field.
func TestRunMigrations_MissingChainColumnsConverge(t *testing.T) {
	fresh, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer fresh.Close()
	want := dumpSchema(t, fresh)

	scenarios := []struct {
		name    string
		version int
		staleFP bool // true = pretend the DB was stamped by an older chain
	}{
		{"version 0 legacy DB", 0, false},
		{"previous-version DB", SchemaVersion - 1, false},
		{"same-version DB, stale chain fingerprint (#328 forgot-to-bump)", SchemaVersion, true},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "legacy.db")
			db, err := sql.Open("sqlite", dbPath)
			require.NoError(t, err)
			defer db.Close()

			// Fully migrate, then strip chain columns to emulate the older shape.
			require.NoError(t, runMigrations(db, dbPath))
			emulateLegacyDB(t, db)
			_, err = db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, sc.version))
			require.NoError(t, err)
			if sc.staleFP {
				_, err = db.Exec(`UPDATE schema_meta SET v = 'older-chain-fingerprint' WHERE k = ?`, chainFingerprintKey)
				require.NoError(t, err)
			}

			require.NoError(t, runMigrations(db, dbPath))

			got := dumpSchema(t, db)
			assertSchemaConverged(t, want, got, fresh, db)
			var stamp int
			require.NoError(t, db.QueryRow(`PRAGMA user_version`).Scan(&stamp))
			require.Equal(t, SchemaVersion, stamp)
			require.Equal(t, chainFingerprint(), storedChainFingerprint(db),
				"chain fingerprint must be re-stamped after healing replay")
		})
	}
}

// TestChainFingerprint_SensitiveToInputs pins the fingerprint's purpose: it
// must change when ANY chain input changes (SQL statement, step revision,
// schema.sql byte). If someone neutralizes the fingerprint (e.g. hashing a
// constant), the self-heal gate silently stops detecting forgotten bumps.
func TestChainFingerprint_SensitiveToInputs(t *testing.T) {
	base := chainFingerprint()
	require.NotEmpty(t, base)

	// Same inputs re-hashed → stable.
	require.Equal(t, base, chainFingerprint())

	// Any single statement change must flip it.
	for _, mutated := range [][]string{
		append([]string{"ALTER TABLE probe_targets ADD COLUMN vantage TEXT NOT NULL DEFAULT 'agent:x'"}, columnMigrations...),
		append(columnMigrations[:1:1], "ALTER TABLE devices ADD COLUMN zz_test TEXT"),
	} {
		orig := columnMigrations
		columnMigrations = mutated
		require.NotEqual(t, base, chainFingerprint(), "fingerprint must change when columnMigrations change")
		columnMigrations = orig
	}

	// Step revision bump must flip it.
	origSteps := migrationStepRevisions
	migrationStepRevisions = append(append([]string{}, origSteps...), "someNewStep rev1")
	require.NotEqual(t, base, chainFingerprint(), "fingerprint must change when a migration step revision is added")
	migrationStepRevisions = origSteps
}

// TestRunMigrations_VersionGateSkipsStampedDB (#268): at SchemaVersion with a
// matching chain fingerprint, the chain is skipped entirely — observable via
// user_version staying put and a dropped core table staying absent (the gate
// must not re-run idempotent steps, keeping startup cheap).
func TestRunMigrations_VersionGateSkipsStampedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gate.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()

	// First run: empty DB, full chain, stamps the version.
	require.NoError(t, runMigrations(db, dbPath))
	var v int
	require.NoError(t, db.QueryRow(`PRAGMA user_version`).Scan(&v))
	require.Equal(t, SchemaVersion, v)

	// Drop a core table, then re-run: the gate must SKIP, leaving the drop in
	// place (pre-gate behavior would have recreated it from schema.sql).
	_, err = db.Exec(`DROP TABLE devices`)
	require.NoError(t, err)
	require.NoError(t, runMigrations(db, dbPath))
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='devices'`).Scan(&count))
	require.Equal(t, 0, count, "gated run must not re-apply schema.sql")
}

// TestRunMigrations_StampedDBGetsChainAdditions regression for the v2 bump:
// #328 appended the probe vantage ALTERs to the chain without bumping
// SchemaVersion, so databases stamped v1 by an earlier binary skipped the
// chain and every probe query died on "no such column: vantage". Reproduce
// exactly that field state — v1-stamped DB missing the vantage columns — and
// require the gate to replay the chain onto it.
func TestRunMigrations_StampedDBGetsChainAdditions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v1-stamped.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()

	// Build the pre-#328 shape: full chain, then strip the vantage columns
	// (and the index that references them).
	require.NoError(t, runMigrations(db, dbPath))
	_, err = db.Exec(`DROP INDEX IF EXISTS idx_probe_results_target_vantage_time`)
	require.NoError(t, err)
	_, err = db.Exec(`ALTER TABLE probe_targets DROP COLUMN vantage`)
	require.NoError(t, err)
	_, err = db.Exec(`ALTER TABLE probe_results DROP COLUMN vantage`)
	require.NoError(t, err)
	// A row that predates the column, and a v1-era version stamp.
	_, err = db.Exec(`INSERT INTO probe_targets (name, module, target) VALUES ('legacy', 'http', 'https://example.com')`)
	require.NoError(t, err)
	_, err = db.Exec(`PRAGMA user_version = 1`)
	require.NoError(t, err)

	require.NoError(t, runMigrations(db, dbPath))

	// The gate must have replayed the chain: version re-stamped, columns back,
	// pre-existing rows backfilled to the DEFAULT.
	var v int
	require.NoError(t, db.QueryRow(`PRAGMA user_version`).Scan(&v))
	require.Equal(t, SchemaVersion, v)
	var targetVantage string
	require.NoError(t, db.QueryRow(`SELECT vantage FROM probe_targets WHERE name='legacy'`).Scan(&targetVantage))
	require.Equal(t, "center", targetVantage)
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM pragma_table_info('probe_targets') WHERE name='vantage'`).Scan(&n))
	require.Equal(t, 1, n)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM pragma_table_info('probe_results') WHERE name='vantage'`).Scan(&n))
	require.Equal(t, 1, n)
}
