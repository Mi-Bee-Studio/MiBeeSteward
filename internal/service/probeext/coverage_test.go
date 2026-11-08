// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

//go:build linux

package probeext

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestNewTracerDefaults pins the zero-value defenses.
func TestNewTracerDefaults(t *testing.T) {
	tr := NewTracer(0, 0, 0)
	if tr.MaxTTL != 30 || tr.PerHop != 500*time.Millisecond || tr.Attempts != 1 {
		t.Fatalf("defaults = %+v", tr)
	}
}

// TestTraceRefusedPort pins the TCP refused branch: a loopback port with no
// listener answers with RST, which still proves the destination was reached.
func TestTraceRefusedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // port now closed

	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	tr := NewTracer(4, 300, 1)
	res := tr.TraceHost(context.Background(), "127.0.0.1", port, "tcp")
	if res.Err != "" {
		t.Fatalf("err: %s", res.Err)
	}
	if res.EndState != "reached" || res.ReachedTTL != 1 {
		t.Fatalf("res = %+v, want refused-but-reached at TTL 1", res)
	}
}

// TestErrQueueOffender pins the sockaddr extraction from an
// sock_extended_err cmsg payload.
func TestErrQueueOffender(t *testing.T) {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint16(data[16:18], syscall.AF_INET)
	copy(data[20:24], []byte{192, 0, 2, 9})
	if got := errQueueOffender(data); got != "192.0.2.9" {
		t.Fatalf("offender = %q", got)
	}
	if got := errQueueOffender(make([]byte, 10)); got != "" {
		t.Fatalf("short buffer must give empty, got %q", got)
	}
	data2 := make([]byte, 24)
	binary.LittleEndian.PutUint16(data2[16:18], syscall.AF_INET6)
	if got := errQueueOffender(data2); got != "" {
		t.Fatalf("non-v4 sockaddr must give empty, got %q", got)
	}
}

// TestOpenStoreBadPath pins the error branch (parent is a regular file).
func TestOpenStoreBadPath(t *testing.T) {
	f := t.TempDir() + "/file"
	if err := writeFile(f, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(f + "/probe_ext.db"); err == nil {
		t.Fatal("unwritable dir must fail")
	}
}

// TestStoreMiscBranches pins the accessors and limit clamps.
func TestStoreMiscBranches(t *testing.T) {
	store := openTestStore(t)
	if store.Conn() == nil {
		t.Fatal("Conn must expose the raw connection")
	}
	ctx := context.Background()
	if err := store.InsertEgressRound(ctx, nil); err != nil {
		t.Fatal(err)
	}
	id, err := store.InsertPathSample(ctx, PathSample{TargetID: 1, Method: "icmp", EndState: "reached", TracedAt: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListPathsByTarget(ctx, id, 0) // 0 clamps to 50
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	var one string
	if err := store.Conn().QueryRowContext(ctx, `SELECT vantage FROM path_samples WHERE id = ?`, id).Scan(&one); err != nil {
		t.Fatal(err)
	}
	if one != "" {
		t.Fatalf("vantage = %q, want the explicit empty value", one)
	}
}

// TestHostPortForTraceFallback pins the malformed-URL fallback for http
// targets without a scheme.
func TestHostPortForTraceFallback(t *testing.T) {
	host, port := hostPortForTrace(testTarget("http", "bare.example.com/path"))
	if host != "bare.example.com/path" || port != 80 {
		t.Fatalf("fallback = %q:%d", host, port)
	}
	host, port = hostPortForTrace(testTarget("tls", "no-port.example.com"))
	if host != "no-port.example.com" || port != 0 {
		t.Fatalf("tls without port = %q:%d", host, port)
	}
}

// TestStartStops pins the scheduler lifecycle: Start with a cancelled
// context exits without hanging.
func TestStartStops(t *testing.T) {
	queries, _ := openTestQueries(t)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)
	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	cancel()
	// The loop exits on the next tick at the latest; nothing to join, just
	// ensure the process does not wedge before the store closes.
	time.Sleep(50 * time.Millisecond)
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
