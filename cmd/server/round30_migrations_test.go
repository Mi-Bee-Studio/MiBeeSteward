// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package main

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// narrowCheck rewrites a table's stored CREATE statement (via the
// writable_schema escape hatch) so one token is REMOVED from a CHECK IN
// list, then the connection is reopened so SQLite reloads the schema. This
// reconstructs the "old narrow CHECK" database shape the chain's extend*
// rebuild helpers exist to repair — without hand-copying 60-line legacy DDL.
func narrowCheck(t *testing.T, path, table, old, replacement string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec(`PRAGMA writable_schema = ON`)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE sqlite_master SET sql = replace(sql, ?, ?) WHERE type = 'table' AND name = ?`,
		old, replacement, table)
	require.NoError(t, err)
	_, err = db.Exec(`PRAGMA writable_schema = OFF`)
	require.NoError(t, err)
	require.NoError(t, db.Close())
}

// freshMigratedDB runs the full chain on a fresh file DB and returns its
// path (reopened by the caller as needed).
func freshMigratedDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "m.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	require.NoError(t, runMigrations(db, path))
	require.NoError(t, db.Close())
	return path
}

// reopen reopens a migrated file DB for assertions.
func reopen(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMigrations_NarrowChecksRebuild drives every extend* table-rebuild
// helper: each table's CHECK is narrowed to the pre-widening shape, and the
// replayed chain must rebuild it wide again (verified by inserting the
// newly-allowed value).
func TestMigrations_NarrowChecksRebuild(t *testing.T) {
	path := freshMigratedDB(t)

	// devices.type loses phone+printer (pre-#248 shape).
	narrowCheck(t, path, "devices", "'camera', 'phone', 'printer'", "'camera'")
	// scan_task_runs.status loses cancelled (pre-#328 shape).
	narrowCheck(t, path, "scan_task_runs", "'failed', 'cancelled')", "'failed')")
	// notification_channels.type loses feishu..discord (pre-#284 shape).
	narrowCheck(t, path, "notification_channels", "'feishu', 'wecom', 'telegram', 'discord'", "'wecom'")

	db := reopen(t, path)
	_, err := db.Exec(`DELETE FROM schema_meta WHERE k = ?`, chainFingerprintKey)
	require.NoError(t, err)
	require.NoError(t, runMigrations(db, path))

	// Every widened CHECK now accepts its probe value.
	for _, probe := range []struct{ stmt string }{
		{`INSERT INTO devices (name, type) VALUES ('p1', 'phone')`},
		{`INSERT INTO scan_task_runs (task_id, status) VALUES (0, 'cancelled')`},
		{`INSERT INTO notification_channels (name, type) VALUES ('p3', 'feishu')`},
	} {
		_, err := db.Exec(probe.stmt)
		require.NoError(t, err, "widened CHECK must accept the probe: %s", probe.stmt)
	}
}

// TestMigrations_NarrowDashboardChecksRebuild narrows BOTH dashboard_configs
// CHECKs (type loses 'list', data_source loses 'builtin') so the rebuild
// helper's probe fails and the table is recreated wide.
func TestMigrations_NarrowDashboardChecksRebuild(t *testing.T) {
	path := freshMigratedDB(t)
	narrowCheck(t, path, "dashboard_configs", "'bar', 'pie', 'list')", "'bar', 'pie')")
	narrowCheck(t, path, "dashboard_configs", "'victoriametrics', 'builtin')", "'victoriametrics')")

	db := reopen(t, path)
	_, err := db.Exec(`DELETE FROM schema_meta WHERE k = ?`, chainFingerprintKey)
	require.NoError(t, err)
	require.NoError(t, runMigrations(db, path))
	_, err = db.Exec(`INSERT INTO dashboard_configs (name, type, data_source, query)
		VALUES ('p', 'list', 'builtin', 'builtin:recent_changes')`)
	require.NoError(t, err, "rebuilt dashboard CHECKs must accept the builtin list widget")
}

// TestMigrations_NarrowUsersRoleRebuild narrows users.role to the original
// admin/user pair; the chain must rebuild it with the four RBAC roles.
func TestMigrations_NarrowUsersRoleRebuild(t *testing.T) {
	path := freshMigratedDB(t)
	narrowCheck(t, path, "users", "'admin', 'operator', 'viewer', 'user'", "'admin', 'user'")

	db := reopen(t, path)
	_, err := db.Exec(`DELETE FROM schema_meta WHERE k = ?`, chainFingerprintKey)
	require.NoError(t, err)
	require.NoError(t, runMigrations(db, path))
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role)
		VALUES ('probe_u', 'probe_u@x.com', 'x', 'operator')`)
	require.NoError(t, err, "rebuilt role CHECK must accept all four roles")
}

// TestMigrations_BackfillsAndDedup drives the data backfills: empty
// device_uuid rows get uuids stamped, unscoped scan tasks adopt their
// network, duplicate-MAC rows merge, and (ip, network) duplicates sweep
// before the unique index is recreated.
func TestMigrations_BackfillsAndDedup(t *testing.T) {
	path := freshMigratedDB(t)
	db := reopen(t, path)

	// Seed: a network, a device with an empty uuid, a duplicate-MAC pair,
	// an unscoped task whose targets sit inside the network, and (after
	// dropping the identity index) an (ip, network) duplicate pair.
	_, err := db.Exec(`
		INSERT INTO networks (id, name, cidr) VALUES (5, 'bk-net', '10.5.0.0/24');
		INSERT INTO devices (name, ip_address, mac_address, status, network_id, device_uuid)
			VALUES ('no-uuid', '10.5.0.7', '', 'online', 5, '');
		INSERT INTO devices (name, ip_address, mac_address, status, network_id, device_uuid)
			VALUES ('dup-a', '10.5.0.8', 'aa:bb:cc:00:00:01', 'online', 5, 'seed-dup-a'),
			       ('dup-b', '10.5.0.9', 'aa:bb:cc:00:00:01', 'online', 5, 'seed-dup-b');
		INSERT INTO scan_tasks (name, targets, cron_expr) VALUES ('bk-task', '10.5.0.0/24', '0 3 * * *');
	`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// Remove the identity index so the duplicate-pair seed below doesn't
	// violate it, then seed two rows on the same (ip, network).
	db = reopen(t, path)
	_, err = db.Exec(`
		DROP INDEX idx_devices_ip_network;
		INSERT INTO devices (name, ip_address, mac_address, status, network_id, device_uuid)
			VALUES ('pair-1', '10.5.0.10', 'aa:bb:cc:00:00:10', 'online', 5, 'seed-p1'),
			       ('pair-2', '10.5.0.10', 'aa:bb:cc:00:00:11', 'online', 5, 'seed-p2');
		CREATE INDEX idx_devices_ip_network ON devices(ip_address, network_id);
	`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// Replay the chain (fingerprint/step tags unchanged here — force it by
	// clearing the recorded fingerprint).
	db = reopen(t, path)
	_, err = db.Exec(`DELETE FROM schema_meta WHERE k = ?`, chainFingerprintKey)
	require.NoError(t, err)
	require.NoError(t, runMigrations(db, path))

	// Empty uuid was stamped; MAC duplicates merged; (ip, network) pair
	// swept to one row; the task adopted the network.
	var uuid string
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE name = 'no-uuid'`).Scan(&uuid))
	require.NotEmpty(t, uuid, "empty device_uuid backfilled")

	var macDups int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = 'aa:bb:cc:00:00:01'`).Scan(&macDups))
	require.Equal(t, 1, macDups, "duplicate-MAC rows merged")

	var ipDups int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address = '10.5.0.10' AND network_id = 5`).Scan(&ipDups))
	require.Equal(t, 1, ipDups, "(ip, network) duplicates swept before the unique index")

	var taskNet sql.NullInt64
	require.NoError(t, db.QueryRow(`SELECT network_id FROM scan_tasks WHERE name = 'bk-task'`).Scan(&taskNet))
	require.True(t, taskNet.Valid, "unscoped task adopted its network")
	require.EqualValues(t, 5, taskNet.Int64)
}
