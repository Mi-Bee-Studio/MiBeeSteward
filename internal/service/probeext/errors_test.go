// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"database/sql"
	"testing"
	"time"

	sqldb "mibee-steward/internal/db"
)

// closedWorld returns a service whose main-DB connection is already closed,
// so every query-backed path takes its error branch.
func closedWorld(t *testing.T) (*Service, *Store) {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	queries := sqldb.New(conn)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t)
	return NewService(testServiceCfg(), store, queries, nil), store
}

// TestSnapshotErrorBranches pins the error paths of the three read surfaces
// once the main DB is unreachable.
func TestSnapshotErrorBranches(t *testing.T) {
	svc, store := closedWorld(t)
	ctx := context.Background()

	// EgressSnapshot reads the ext store, not the main DB: it succeeds empty.
	if _, err := svc.EgressSnapshot(ctx); err != nil {
		t.Fatalf("EgressSnapshot must not touch the main DB: %v", err)
	}
	if _, err := svc.PathsSnapshot(ctx); err == nil {
		t.Fatal("PathsSnapshot with a dead main DB must error")
	}
	if _, err := svc.TraceNow(ctx, 1); err == nil {
		t.Fatal("TraceNow with a dead main DB must error")
	}
	// Store-level error branches: close the ext store too.
	store.Close()
	if _, err := store.LatestPaths(ctx, ""); err == nil {
		t.Fatal("LatestPaths on a closed store must error")
	}
	if err := store.Prune(ctx, time.Now().UTC().Format(time.RFC3339)); err == nil {
		t.Fatal("Prune on a closed store must error")
	}
}

// TestTraceTargetBadHost pins the "cannot derive host" sample path: an http
// target with an empty string yields a stored error sample, not a crash.
func TestTraceTargetBadHost(t *testing.T) {
	queries, conn := openTestQueries(t)
	insertTarget(t, conn, 21, "broken", "http", "", "manual", true, nil)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)
	sample, err := svc.traceTarget(context.Background(), mustGet(t, queries, 21), "baseline")
	if err != nil {
		t.Fatalf("stored-error sample must not fail the call: %v", err)
	}
	if sample.EndState != "error" || sample.Err != "cannot derive host from target" {
		t.Fatalf("sample = %+v", sample)
	}
}

// TestQueryPathsBadHopsJSON pins the tolerant decode: a row whose hops
// column holds invalid JSON still lists with empty hops.
func TestQueryPathsBadHopsJSON(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if _, err := store.Conn().ExecContext(ctx,
		`INSERT INTO path_samples (target_id, vantage, method, end_state, hops, traced_at)
		 VALUES (1, 'center', 'tcp', 'reached', 'not-json', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListPathsByTarget(ctx, 1, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if rows[0].Hops == nil || len(rows[0].Hops) != 0 {
		t.Fatalf("hops = %+v, want empty non-nil", rows[0].Hops)
	}
}
