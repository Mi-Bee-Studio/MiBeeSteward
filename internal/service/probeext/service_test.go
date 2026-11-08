// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// openTestQueries builds an in-memory main DB with the probe_targets table
// (the minimal slice of db/schema.sql the service reads). Returns the
// queries plus the raw connection for test-row inserts.
func openTestQueries(t *testing.T) (*db.Queries, *sql.DB) {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Exec(`CREATE TABLE probe_targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		module TEXT NOT NULL,
		target TEXT NOT NULL,
		interval_seconds INTEGER NOT NULL DEFAULT 60,
		timeout_seconds INTEGER NOT NULL DEFAULT 10,
		enabled INTEGER NOT NULL DEFAULT 1,
		notes TEXT NOT NULL DEFAULT '',
		last_run_at TEXT NOT NULL DEFAULT '',
		last_status TEXT NOT NULL DEFAULT '',
		last_latency_ms REAL NOT NULL DEFAULT 0,
		last_error TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		vantage TEXT NOT NULL DEFAULT 'center',
		options TEXT NOT NULL DEFAULT '',
		device_id INTEGER,
		source TEXT NOT NULL DEFAULT 'manual'
	)`); err != nil {
		t.Fatal(err)
	}
	return db.New(conn), conn
}

func insertTarget(t *testing.T, conn *sql.DB, id int64, name, module, target, source string, enabled bool, deviceID any) {
	t.Helper()
	var dev any
	if deviceID != nil {
		dev = deviceID
	}
	if _, err := conn.ExecContext(context.Background(),
		`INSERT INTO probe_targets (id, name, module, target, enabled, source, device_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, module, target, enabled, source, dev); err != nil {
		t.Fatal(err)
	}
}

func testServiceCfg() config.ProbeConfig {
	return config.ProbeConfig{
		Egress: config.ProbeEgressConfig{Enabled: false, IntervalSeconds: 300},
		Trace: config.ProbeTraceConfig{
			Categories:      []string{"external", "quality"},
			IntervalMinutes: 30,
			MaxTTL:          8,
			PerHopMs:        200,
			Concurrency:     2,
		},
	}
}

// TestTraceTargetPersists pins the target → trace → store chain against a
// loopback HTTP target: reached sample with hops carrying their TTL.
func TestTraceTargetPersists(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	queries, conn := openTestQueries(t)
	insertTarget(t, conn, 1, "local-site", "http", srv.URL, "manual", true, nil)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)

	sample, err := svc.traceTarget(context.Background(), mustGet(t, queries, 1), "baseline")
	if err != nil {
		t.Fatalf("traceTarget: %v", err)
	}
	if sample.EndState != "reached" || sample.ReachedTTL != 1 || sample.VisibleHops != 1 {
		t.Fatalf("sample = %+v", sample)
	}
	if sample.Hops[0].TTL != 1 || sample.Hops[0].IP != "127.0.0.1" {
		t.Fatalf("hop = %+v, want TTL 1 destination 127.0.0.1", sample.Hops[0])
	}
}

// TestTraceNowAndSnapshots pins the manual trigger + both snapshot payloads
// (module/category enrichment from the targets table).
func TestTraceNowAndSnapshots(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	queries, conn := openTestQueries(t)
	insertTarget(t, conn, 7, "biz-site", "http", srv.URL, "manual", true, nil)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)

	sample, err := svc.TraceNow(context.Background(), 7)
	if err != nil {
		t.Fatalf("TraceNow: %v", err)
	}
	if sample.Trigger != "manual" || sample.TargetName != "biz-site" {
		t.Fatalf("sample = %+v", sample)
	}
	if _, err := svc.TraceNow(context.Background(), 999); err == nil {
		t.Fatal("unknown target must error")
	}

	paths, err := svc.PathsSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths = %+v", paths)
	}
	if paths[0]["module"] != "http" || paths[0]["category"] != "external" || paths[0]["target_name"] != "biz-site" {
		t.Fatalf("enrichment missing: %+v", paths[0])
	}
	hist, err := svc.ListTargetPaths(context.Background(), 7, 10)
	if err != nil || len(hist) != 1 {
		t.Fatalf("history = %+v err=%v", hist, err)
	}
	eg, err := svc.EgressSnapshot(context.Background())
	if err != nil || len(eg) != 0 {
		t.Fatalf("egress snapshot with no rounds = %+v err=%v", eg, err)
	}
}

// TestTraceDueTargetsCategoryFilter pins the category allow-list: an enabled
// external target gets traced, a lan (device-bound) one never does, a
// disabled one neither.
func TestTraceDueTargetsCategoryFilter(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	queries, conn := openTestQueries(t)
	insertTarget(t, conn, 1, "ext", "http", srv.URL, "manual", true, nil)
	insertTarget(t, conn, 2, "lan", "http", srv.URL, "auto", true, 55)
	insertTarget(t, conn, 3, "off", "http", srv.URL, "manual", false, nil)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)

	// First tick seeds the stagger; second tick (interval forced due by
	// rewinding the schedule) traces.
	now := time.Now()
	svc.traceDueTargets(context.Background(), now)
	svc.mu.Lock()
	for id := range svc.nextTrace {
		svc.nextTrace[id] = now.Add(-time.Minute)
	}
	svc.mu.Unlock()
	svc.traceDueTargets(context.Background(), now.Add(time.Second))

	paths, err := store.LatestPaths(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0].TargetName != "ext" {
		t.Fatalf("paths = %+v, want exactly the external target", paths)
	}
}

// TestTraceCategoryOK pins the allow-list helper itself.
func TestTraceCategoryOK(t *testing.T) {
	q2, _ := openTestQueries(t)
	svc := NewService(testServiceCfg(), openTestStore(t), q2, nil)
	if !svc.traceCategoryOK("external") || !svc.traceCategoryOK("quality") {
		t.Fatal("configured categories must pass")
	}
	if svc.traceCategoryOK("lan") {
		t.Fatal("lan is not in the default set")
	}
}

func mustGet(t *testing.T, q *db.Queries, id int64) (row db.ProbeTarget) {
	t.Helper()
	var err error
	row, err = q.GetProbeTarget(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return row
}
