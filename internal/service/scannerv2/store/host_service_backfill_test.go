// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func sqlNullInt64(id int64) sql.NullInt64 {
	return sql.NullInt64{Int64: id, Valid: true}
}

// TestBackfillHostServiceUUIDs pins the #612 heal: host_services rows written
// before their device row existed (device_uuid still empty) get the uuid of
// the device now holding their ip, rows without any device row stay empty,
// and rows already resolved are untouched. The second run is a no-op
// (idempotent).
func TestBackfillHostServiceUUIDs(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)

	// Device rows: .10 has a fresh row, plus a stale twin at the same ip in a
	// DIFFERENT network (the (ip, network_id) unique index allows that) — the
	// most recently seen one must win the subquery.
	seedDeviceRowWithUUID(t, conn, "10.0.0.10", "aa:bb:cc:dd:ee:10", nid, "uuid-recent")
	_, err := conn.ExecContext(ctx,
		`UPDATE devices SET last_seen = '2026-10-19T00:00:00Z' WHERE device_uuid = 'uuid-recent'`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO networks (id, name, cidr, site, created_at, updated_at)
		 VALUES (2, 'n2', '10.0.1.0/24', 's', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	seedDeviceRowWithUUID(t, conn, "10.0.0.10", "aa:bb:cc:dd:ee:99", sqlNullInt64(2), "uuid-stale")

	insert := func(ip, devUUID, service string, port int) {
		t.Helper()
		_, err := conn.ExecContext(ctx,
			`INSERT INTO host_services (ip, device_uuid, service, port) VALUES (?, ?, ?, ?)`,
			ip, devUUID, service, port)
		require.NoError(t, err)
	}
	insert("10.0.0.10", "", "http", 80)            // healable: a device row now exists
	insert("10.0.0.10", "uuid-fixed", "rtsp", 554) // already resolved: must not change
	insert("10.0.0.99", "", "ssh", 22)             // no device row: stays empty

	n, err := repo.BackfillHostServiceUUIDs(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "exactly the one healable row changes")

	uuidOf := func(service string, port int) string {
		t.Helper()
		var u string
		require.NoError(t, conn.QueryRowContext(ctx,
			`SELECT device_uuid FROM host_services WHERE service = ? AND port = ?`, service, port).Scan(&u))
		return u
	}
	require.Equal(t, "uuid-recent", uuidOf("http", 80), "healed to the most-recently-seen device at the ip")
	require.Equal(t, "uuid-fixed", uuidOf("rtsp", 554), "already-resolved row untouched")
	require.Equal(t, "", uuidOf("ssh", 22), "row without any device row stays ''")

	// Idempotent: nothing left to heal.
	n2, err := repo.BackfillHostServiceUUIDs(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(0), n2)
}
