// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package flows

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	_ "modernc.org/sqlite"

	dbsql "mibee-steward/db"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2/ebpf"
)

// setupFlowTest creates the minimal schema the ingester touches plus two
// managed devices and one network.
func setupFlowTest(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// One pooled connection: every :memory: connection is a SEPARATE empty
	// database, so the pool must never hand out a second one.
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { conn.Close() })
	// The production schema, embedded — hand-maintained inline DDL drifts
	// from the real column lists (GetDeviceByIP scans every devices column).
	if _, err := conn.Exec(dbsql.SchemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}
	queries := db.New(conn)
	if _, err := conn.Exec(`INSERT INTO networks (name, cidr) VALUES ('test-lan', '192.0.2.0/24')`); err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct{ ip, name string }{
		{"192.0.2.10", "camera"},
		{"192.0.2.20", "nas"},
	} {
		if _, err := conn.Exec(`INSERT INTO devices (device_uuid, name, ip_address, network_id) VALUES (?, ?, ?, 1)`,
			"uuid-"+d.ip, d.name, d.ip); err != nil {
			t.Fatal(err)
		}
	}
	watcher := changedetect.NewWatcher(slog.Default())
	svc := NewService(conn, queries, watcher, slog.Default())
	return svc, conn
}

func TestIngestPersistsAggregatesAndFirstSeenEvent(t *testing.T) {
	svc, conn := setupFlowTest(t)
	sub := svc.watcher.Subscribe()
	t.Cleanup(func() { svc.watcher.Unsubscribe(sub) })

	svc.Ingest(context.Background(), []ebpf.FlowSample{
		{SrcIP: "192.0.2.10", DstIP: "192.0.2.20", Proto: 6, Dport: 445, Bytes: 1000, Packets: 10},
		{SrcIP: "192.0.2.20", DstIP: "192.0.2.10", Proto: 6, Dport: 50000, Bytes: 400, Packets: 8},
		{SrcIP: "192.0.2.10", DstIP: "198.51.100.9", Proto: 17, Dport: 53, Bytes: 75, Packets: 1},
	})

	// Two managed rows (mirrored) + one external-peer row on .10.
	rows, err := conn.Query(`SELECT device_id, peer_ip, peer_device_id, bytes_out, bytes_in FROM device_speaks_with ORDER BY peer_ip`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []struct {
		device, peer                   int64
		ip                             string
		out, in                        int64
	}
	for rows.Next() {
		var r struct {
			device, peer                   int64
			ip                             string
			out, in                        int64
		}
		var peerID sql.NullInt64
		if err := rows.Scan(&r.device, &r.ip, &peerID, &r.out, &r.in); err != nil {
			t.Fatal(err)
		}
		r.peer = peerID.Int64
		got = append(got, r)
	}
	if len(got) != 3 {
		t.Fatalf("rows = %+v, want 3", got)
	}
	byPeer := map[string]struct{ device, peer, out, in int64 }{}
	for _, r := range got {
		byPeer[r.ip] = struct{ device, peer, out, in int64 }{r.device, r.peer, r.out, r.in}
	}
	if r := byPeer["192.0.2.20"]; r.device != 1 || r.peer != 2 || r.out != 1000 || r.in != 400 {
		t.Fatalf(".10 -> .20 row = %+v", r)
	}
	if r := byPeer["192.0.2.10"]; r.device != 2 || r.peer != 1 || r.out != 400 || r.in != 1000 {
		t.Fatalf(".20 -> .10 row = %+v", r)
	}
	if r := byPeer["198.51.100.9"]; r.device != 1 || r.peer != 0 || r.out != 75 || r.in != 0 {
		t.Fatalf("external row = %+v", r)
	}

	// Exactly one first-seen event (managed pair), none for the external peer.
	select {
	case row := <-sub:
		if row.ChangeType != changedetect.ChangeTypeSpeaksWithNew {
			t.Fatalf("change_type = %s", row.ChangeType)
		}
		if row.EntityID == nil || *row.EntityID != 1 {
			t.Fatalf("entity_id = %v", row.EntityID)
		}
	default:
		t.Fatal("expected a speaks_with_new event on the watcher")
	}
	select {
	case row := <-sub:
		t.Fatalf("unexpected extra event: %+v", row)
	default:
	}
}

func TestIngestSecondBatchIncrementsWithoutNewEvent(t *testing.T) {
	svc, conn := setupFlowTest(t)
	sub := svc.watcher.Subscribe()
	t.Cleanup(func() { svc.watcher.Unsubscribe(sub) })
	ctx := context.Background()

	batch := []ebpf.FlowSample{{SrcIP: "192.0.2.10", DstIP: "192.0.2.20", Bytes: 100}}
	svc.Ingest(ctx, batch)
	<-sub // consume the first-seen event

	svc.Ingest(ctx, batch)
	select {
	case row := <-sub:
		t.Fatalf("second batch must not re-emit: %+v", row)
	default:
	}
	var out, in int64
	if err := conn.QueryRow(`SELECT bytes_out, bytes_in FROM device_speaks_with WHERE device_id = 1`).Scan(&out, &in); err != nil {
		t.Fatal(err)
	}
	if out != 200 || in != 0 {
		t.Fatalf("accumulated = %d/%d, want 200/0", out, in)
	}
}

func TestIngestUnmanagedLanHostDropped(t *testing.T) {
	svc, conn := setupFlowTest(t)
	// .99 is inside the prefix but has no devices row.
	svc.Ingest(context.Background(), []ebpf.FlowSample{
		{SrcIP: "192.0.2.99", DstIP: "198.51.100.1", Bytes: 50},
	})
	var n int
	if err := conn.QueryRow(`SELECT count(*) FROM device_speaks_with`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
}
