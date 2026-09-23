// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package discovery

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// quietDisc swaps the package logger for a discarding one.
func quietDisc(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// TestIdentify_NilEngineAndFailedScan pins Identify's degrade contract: with
// no identification engine wired (or a failing scan) it reports not-found
// instead of panicking, passive discovery stays observation-only.
func TestIdentify_NilEngineAndFailedScan(t *testing.T) {
	quietDisc(t)
	ident := &engineIdentifier{}
	rep, ok := ident.Identify(context.Background(), "10.0.0.1")
	require.False(t, ok)
	require.False(t, rep.Alive)
}

// TestObserve_CapEviction: an unseen IP observed while the cache is at cap
// evicts one stale entry instead of growing unbounded.
func TestObserve_CapEviction(t *testing.T) {
	quietDisc(t)
	svc := New(Config{}, nil, nil, nil, 0, nil, slog.Default())

	for i := 0; i < maxObservedIPs; i++ {
		svc.Observe(ipOf(i), scannerv2.Evidence{Kind: "mdns", IP: ipOf(i)})
	}
	require.Len(t, svc.obs, maxObservedIPs)

	svc.Observe("10.9.9.9", scannerv2.Evidence{Kind: "mdns", IP: "10.9.9.9"})
	svc.obsMu.Lock()
	size := len(svc.obs)
	svc.obsMu.Unlock()
	require.Equal(t, maxObservedIPs, size, "cap holds: one stale entry evicted for the newcomer")

	// Re-observing a KNOWN ip at cap must not evict anything.
	svc.Observe(ipOf(0), scannerv2.Evidence{Kind: "ssdp", IP: ipOf(0)})
	svc.obsMu.Lock()
	size = len(svc.obs)
	svc.obsMu.Unlock()
	require.Equal(t, maxObservedIPs, size)
}

func ipOf(i int) string {
	return fmt.Sprintf("10.%d.%d.7", i/256, i%256)
}

// TestEmit_DropsWhenChannelFull: a full event channel drops with a debug log
// instead of blocking the source goroutine.
func TestEmit_DropsWhenChannelFull(t *testing.T) {
	quietDisc(t)
	svc := New(Config{}, nil, nil, nil, 0, nil, slog.Default())

	for i := 0; i < cap(svc.events); i++ {
		svc.Emit(NewHostEvent{IP: ipOf(i), Source: "test"})
	}
	// Channel now full, one more must not block.
	done := make(chan struct{})
	go func() {
		svc.Emit(NewHostEvent{IP: "10.8.8.8", Source: "test"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit must not block on a full channel")
	}
}
