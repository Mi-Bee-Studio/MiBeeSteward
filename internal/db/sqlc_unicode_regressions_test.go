// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package db_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// TestQueriesFilesASCIIOnly pins the #290 root cause: sqlc v1.31.1 corrupts
// the tail of a regenerated SQL constant when the query file contains
// multi-byte characters (em-dash, "<>", ...). The corruption is
// POSITION-DEPENDENT - the same file can pass CI for months and break the
// moment an unrelated edit shifts byte offsets onto a multi-byte rune - so
// "the current output looks fine" proves nothing. Zero non-ASCII input is the
// only reliable defense; db/schema.sql is exempt (schema comments never feed
// the statement-reconstruction path that corrupts).
func TestQueriesFilesASCIIOnly(t *testing.T) {
	dir := queriesDir(t)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var offenders []string
	found := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		found = true
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		for i, line := range strings.Split(string(content), "\n") {
			for _, r := range line {
				if r > 0x7F {
					offenders = append(offenders, fmt.Sprintf(
						"%s:%d: non-ASCII %q (U+%04X) - rewrite the comment in ASCII",
						e.Name(), i+1, string(r), r))
				}
			}
		}
	}
	require.True(t, found, "no .sql files found under %s - path resolution broke", dir)
	require.Empty(t, offenders,
		"db/queries/*.sql must stay pure ASCII (sqlc unicode-comment corruption, #290):\n%s",
		strings.Join(offenders, "\n"))
}

// queriesDir resolves the repo's db/queries directory relative to this test
// file, independent of the working directory `go test` happens to use.
func queriesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "db", "queries")
}

// TestDeleteProbeResultsStaleBatched_Executes is the runtime half of the #290
// regression suite: the corrupted constant (`... LIMIT ?` missing its closing
// paren) parsed fine at Go compile time and only exploded as
// "SQL logic error: incomplete input" when the retention sweep ran - on the
// real router it failed on every startup. Executing the query proves the
// generated statement parses AND deletes exactly the stale rows.
func TestDeleteProbeResultsStaleBatched_Executes(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	ctx := context.Background()

	res, err := conn.Exec(`INSERT INTO probe_targets (name, module, target) VALUES ('t1', 'http', 'https://example.com')`)
	require.NoError(t, err)
	targetID, err := res.LastInsertId()
	require.NoError(t, err)

	// Two stale rows (RFC3339 sorts lexically), one fresh.
	for _, checkedAt := range []string{
		"2026-01-01T00:00:00Z",
		"2026-01-02T00:00:00Z",
		"2026-09-01T00:00:00Z",
	} {
		_, err = conn.Exec(`INSERT INTO probe_results (target_id, status, checked_at) VALUES (?, 'success', ?)`,
			targetID, checkedAt)
		require.NoError(t, err)
	}

	deleted, err := q.DeleteProbeResultsStaleBatched(ctx, db.DeleteProbeResultsStaleBatchedParams{
		CheckedAt: "2026-08-01T00:00:00Z",
		Limit:     500,
	})
	require.NoError(t, err, "the #290-corrupted statement failed here with 'incomplete input'")
	require.EqualValues(t, 2, deleted)

	var remaining int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM probe_results`).Scan(&remaining))
	require.Equal(t, 1, remaining, "only the fresh row must survive")
}

// TestUpdateDeviceStatus_Executes covers the second query the #290 corruption
// hit: the generated constant lost the `?` after `WHERE id =`, which a bare
// parse smoke test catches and the offline_since CASE semantics exercise too.
func TestUpdateDeviceStatus_Executes(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	ctx := context.Background()

	res, err := conn.Exec(`INSERT INTO devices (name, ip_address, status) VALUES ('d1', '192.168.64.1', 'online')`)
	require.NoError(t, err)
	devID, err := res.LastInsertId()
	require.NoError(t, err)

	flip := func(status string) {
		require.NoError(t, q.UpdateDeviceStatus(ctx, db.UpdateDeviceStatusParams{
			Status:  status,
			Column2: status,
			Column3: status,
			ID:      devID,
		}))
	}

	flip("offline")
	var status string
	var offlineSince *string
	require.NoError(t, conn.QueryRow(`SELECT status, offline_since FROM devices WHERE id = ?`, devID).
		Scan(&status, &offlineSince))
	require.Equal(t, "offline", status)
	require.NotNil(t, offlineSince, "transitioning TO offline must stamp offline_since")

	flip("online")
	require.NoError(t, conn.QueryRow(`SELECT status, offline_since FROM devices WHERE id = ?`, devID).
		Scan(&status, &offlineSince))
	require.Equal(t, "online", status)
	require.Nil(t, offlineSince, "transitioning TO online must clear offline_since")
}

// TestListTopologyEdgesByNetwork_Executes covers the third #290 casualty: the
// constant ended mid-identifier (`ORDER BY ... DESC, te.`), so the topology
// graph listing would have failed at runtime had anything called it.
func TestListTopologyEdgesByNetwork_Executes(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	ctx := context.Background()

	var a, b int64
	for i, name := range []string{"sw-a", "sw-b"} {
		res, err := conn.Exec(`INSERT INTO devices (name, ip_address, status, network_id, device_uuid) VALUES (?, ?, 'online', 1, ?)`,
			name, fmt.Sprintf("192.168.64.%d", 10+i), fmt.Sprintf("uuid-edge-%d", i))
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		if i == 0 {
			a = id
		} else {
			b = id
		}
	}

	_, err = conn.Exec(`INSERT INTO topology_edges (from_device_id, to_device_id, edge_type, via_protocol, metadata)
		VALUES (?, ?, 'l2', 'LLDP', '{}')`, a, b)
	require.NoError(t, err)

	nid := int64(1)
	edges, err := q.ListTopologyEdgesByNetwork(ctx, db.ListTopologyEdgesByNetworkParams{
		Column1:     nid,
		NetworkID:   &nid,
		NetworkID_2: &nid,
	})
	require.NoError(t, err, "the #290-corrupted statement failed here with 'incomplete input'")
	require.Len(t, edges, 1)
	require.Equal(t, "l2", edges[0].EdgeType)
}
