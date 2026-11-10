// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//go:build linux

package probeext

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"syscall"
	"testing"
	"time"

	sqldb "mibee-steward/internal/db"
)

// TestTraceDueTargetsListError pins the list-failure warn branch: a closed
// main DB must not panic the scheduler.
func TestTraceDueTargetsListError(t *testing.T) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	queries := sqldb.New(conn)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	svc := NewService(testServiceCfg(), openTestStore(t), queries, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.traceDueTargets(context.Background(), time.Now()) // warn + return
}

// TestTraceICMPGatewayTTL1 exercises the ICMP error-queue branch against
// the real first hop: a TTL=1 echo to an off-link public address makes the
// default gateway answer Time-Exceeded (most do). Tolerant: if this
// environment's gateway stays silent the walk still ends, and we only
// assert the non-panicking terminal states.
func TestTraceICMPGatewayTTL1(t *testing.T) {
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP); err != nil {
		t.Skipf("no unprivileged ICMP ping sockets here: %v", err)
	} else {
		syscall.Close(fd)
	}
	tr := NewTracer(1, 400, 1)
	res := tr.TraceHost(context.Background(), "223.5.5.5", 0, "icmp")
	if res.Err != "" {
		t.Fatalf("err: %s", res.Err)
	}
	// Either the gateway answered (visible hop at TTL 1) or everything
	// stayed silent (max_ttl with an empty first hop).
	if res.EndState != "max_ttl" {
		t.Fatalf("end state = %q, want max_ttl at TTL1", res.EndState)
	}
	if res.Hops[0].IP != "" && res.Hops[0].IP == "223.5.5.5" {
		t.Fatalf("TTL1 hop is the destination - loopback route?")
	}
}
