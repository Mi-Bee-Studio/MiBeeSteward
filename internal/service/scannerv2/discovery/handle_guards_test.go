// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package discovery

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// recSink37 captures Apply calls.
type recSink37 struct{ reports []scannerv2.HostReport }

func (r *recSink37) Apply(_ context.Context, rep scannerv2.HostReport) bool {
	r.reports = append(r.reports, rep)
	return true
}

func newDiscSvc37(sink HostSink, db *sql.DB) *Service {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(Config{}, sink, nil, db, 0, nil, logger)
}

// TestHandle37_GuardsAndDedup drives handle's decision ladder directly: the
// empty-IP guard, the synthesize path for an unknown host (no DB, no
// identification engine), and the recent-dedup suppression on repeat.
func TestHandle37_GuardsAndDedup(t *testing.T) {
	ctx := context.Background()
	sink := &recSink37{}
	svc := newDiscSvc37(sink, nil)

	svc.handle(ctx, NewHostEvent{IP: "", Source: "test"})
	require.Empty(t, sink.reports)

	svc.handle(ctx, NewHostEvent{IP: "10.0.0.1", Source: "test"})
	require.Len(t, sink.reports, 1, "unknown host (nil DB) synthesizes a report")

	svc.handle(ctx, NewHostEvent{IP: "10.0.0.1", Source: "test"})
	require.Len(t, sink.reports, 1, "repeat inside dedupTTL is suppressed")
}

// TestHandle37_KnownHostSkippedAndRingTrim: with a DB wired, an existing
// device row makes handle skip; a burst past the recent-event ring capacity
// trims it back to the cap.
func TestHandle37_KnownHostSkippedAndRingTrim(t *testing.T) {
	ctx := context.Background()
	conn := memoryDB(t)

	sink := &recSink37{}
	svc := newDiscSvc37(sink, conn)

	_, err := conn.Exec(`INSERT INTO devices (name, ip_address, mac_address, status, device_uuid)
		VALUES ('known', '10.0.0.9', 'aa:bb:cc:dd:ee:09', 'online', 'seed-10.0.0.9')`)
	require.NoError(t, err)

	svc.handle(ctx, NewHostEvent{IP: "10.0.0.9", Source: "test"})
	require.Empty(t, sink.reports, "a known host never synthesizes")

	for i := 0; i < 30; i++ {
		svc.handle(ctx, NewHostEvent{IP: fmt.Sprintf("10.1.%d.%d", i/10, i%10), Source: "test"})
	}
	require.Len(t, svc.lastEvents, maxRecentEvents, "recent-event ring trims to capacity")
}

// Start/Stop cycling concurrent with Status() reads must be race-free (the
// status endpoint runs on its own goroutine). Run under -race; also pins the
// Enabled flag flipping with the lifecycle.
func TestDiscovery_StartStopStatusConcurrent(t *testing.T) {
	conn := memoryDB(t)
	svc := newDiscSvc37(&recSink37{}, conn)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = svc.Status()
			}
		}
	}()

	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		svc.Start(ctx)
		require.True(t, svc.Status().Enabled, "started service reports enabled")
		svc.Stop()
		require.False(t, svc.Status().Enabled, "stopped service reports disabled")
		cancel()
	}
	close(stop)
	wg.Wait()
}
