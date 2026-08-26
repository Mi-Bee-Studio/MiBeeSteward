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
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestOpenAgentDB_MigratesLegacyDB pins #337: a mini-DB created by an older
// agent (devices table without offline_since / device_uuid /
// ssh_credential_id) must be brought up to shape on startup — CREATE TABLE IF
// NOT EXISTS alone leaves legacy tables untouched and every identity query
// touching the new columns fails (observed in the wild as constant
// "no such column: offline_since" WARNs with degraded roam/replace).
func TestOpenAgentDB_MigratesLegacyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/legacy.db"

	// Provision a legacy DB: old devices shape + one row.
	legacy, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = legacy.Exec(`CREATE TABLE devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'other', brand TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
		location TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'unknown', ip_address TEXT NOT NULL DEFAULT '', mac_address TEXT NOT NULL DEFAULT '',
		serial_number TEXT NOT NULL DEFAULT '', purchase_date TEXT NOT NULL DEFAULT '', warranty_expiry TEXT NOT NULL DEFAULT '',
		tags TEXT NOT NULL DEFAULT '{}', scan_source TEXT NOT NULL DEFAULT 'manual', prometheus_labels TEXT NOT NULL DEFAULT '{}',
		last_scanned_at TIMESTAMP, last_scan_task_id INTEGER, open_ports TEXT NOT NULL DEFAULT '[]',
		detected_services TEXT NOT NULL DEFAULT '[]', prometheus_url TEXT NOT NULL DEFAULT '', node_exporter_url TEXT NOT NULL DEFAULT '',
		last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
		scan_attributes TEXT NOT NULL DEFAULT '{}', user_attributes TEXT NOT NULL DEFAULT '{}',
		network_id INTEGER, first_seen TIMESTAMP, last_seen TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = legacy.Exec(`INSERT INTO devices (name, ip_address) VALUES ('legacy-host', '192.168.62.10')`)
	require.NoError(t, err)
	require.NoError(t, legacy.Close())

	// openAgentDB must migrate it in place and keep the data readable.
	conn, err := openAgentDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	for _, col := range []string{"offline_since", "device_uuid", "ssh_credential_id"} {
		var n int
		require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = ?`, col).Scan(&n), col)
		require.Equal(t, 1, n, "column %s must exist after migration", col)
	}
	var name, uuid string
	require.NoError(t, conn.QueryRow(`SELECT name, device_uuid FROM devices WHERE ip_address='192.168.62.10'`).Scan(&name, &uuid))
	require.Equal(t, "legacy-host", name)
	require.Equal(t, "", uuid, "backfill default for device_uuid")

	// Idempotence: a second open must succeed unchanged.
	require.NoError(t, conn.Close())
	conn2, err := openAgentDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { conn2.Close() })
	for _, col := range []string{"credential_id", "network_id"} {
		var n int
		require.NoError(t, conn2.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('scan_tasks') WHERE name = ?`, col).Scan(&n), col)
		require.Equal(t, 1, n, "scan_tasks.%s must exist after migration", col)
	}
	var cols int
	require.NoError(t, conn2.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('devices')`).Scan(&cols))
}
