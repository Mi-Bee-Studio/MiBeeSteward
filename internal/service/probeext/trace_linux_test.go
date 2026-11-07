// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

//go:build linux

package probeext

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTraceLoopbackTCP pins the unprivileged TCP tracer against a loopback
// listener: the destination must answer at TTL 1 (loopback is on-link), the
// end state must be reached, and the responder's port must be the trace
// port. Runs with zero capabilities (plain test process).
func TestTraceLoopbackTCP(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.URL[len("http://"):])
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	tr := NewTracer(8, 300, 1)
	res := tr.TraceHost(context.Background(), host, port, "tcp")
	if res.Err != "" {
		t.Fatalf("trace err: %s", res.Err)
	}
	if res.Method != "tcp" || res.EndState != "reached" || res.ReachedTTL != 1 {
		t.Fatalf("res = %+v", res)
	}
	if res.DstIP != "127.0.0.1" {
		t.Errorf("dst = %q, want 127.0.0.1", res.DstIP)
	}
}

// TestTraceLoopbackICMP pins the ping-socket tracer the same way.
func TestTraceLoopbackICMP(t *testing.T) {
	tr := NewTracer(8, 300, 1)
	res := tr.TraceHost(context.Background(), "127.0.0.1", 0, "icmp")
	if res.Err != "" {
		t.Fatalf("trace err: %s (ping_group_range may exclude this GID)", res.Err)
	}
	if res.EndState != "reached" || res.ReachedTTL != 1 {
		t.Fatalf("res = %+v", res)
	}
	// Loopback replies keep the default TTL (64 on Linux); whatever it is,
	// the cmsg path must have produced a positive reply TTL.
	if res.ReplyTTL <= 0 || res.ReplyTTL > 255 {
		t.Errorf("reply ttl = %d, want 1..255", res.ReplyTTL)
	}
}

// TestTraceUnresolvable pins the error end-state.
func TestTraceUnresolvable(t *testing.T) {
	tr := NewTracer(4, 100, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := tr.TraceHost(ctx, "no-such-host.invalid", 0, "icmp")
	if res.EndState != "error" || res.Err == "" {
		t.Fatalf("res = %+v, want error end state", res)
	}
}
