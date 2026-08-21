// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package db_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// TestCreateScanResult_RescanUpserts is the regression test for #253: a
// periodic task rescans the same (task_id, ip) every cycle. The plain INSERT
// failed the UNIQUE(task_id, ip) index on every rescan, freezing the stored
// snapshot until the retention sweep deleted the old row. The upsert must
// replace the row in place and refresh scanned_at.
func TestCreateScanResult_RescanUpserts(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	ctx := context.Background()

	res, err := conn.Exec(`INSERT INTO scan_tasks (name, targets) VALUES ('periodic', '192.168.63.0/24')`)
	require.NoError(t, err)
	taskID, err := res.LastInsertId()
	require.NoError(t, err)

	first := db.CreateScanResultParams{
		TaskID: taskID, Ip: "192.168.63.1", Alive: 1, RttMs: 12,
		Ports: "[22]", Services: "{}", SnmpData: "{}",
	}
	row1, err := q.CreateScanResult(ctx, first)
	require.NoError(t, err, "first scan of an IP must insert")

	// Same (task_id, ip) again — different run, fresher data. Before #253 this
	// returned "UNIQUE constraint failed: scan_results.task_id, scan_results.ip".
	row2, err := q.CreateScanResult(ctx, db.CreateScanResultParams{
		TaskID: taskID, Ip: "192.168.63.1", Alive: 0, RttMs: 0,
		Ports: "[]", Services: "{}", SnmpData: "{}",
	})
	require.NoError(t, err, "rescan of the same (task_id, ip) must upsert, not fail")
	require.Equal(t, row1.ID, row2.ID, "upsert must replace the existing row, not add a second one")
	require.EqualValues(t, 0, row2.Alive, "upsert must apply the new scan's data")
	require.False(t, row2.ScannedAt.Before(row1.ScannedAt), "upsert must refresh scanned_at")

	var count int
	require.NoError(t, conn.QueryRow("SELECT COUNT(*) FROM scan_results WHERE task_id = ?", taskID).Scan(&count))
	require.Equal(t, 1, count, "one (task_id, ip) pair must stay one row")
}
