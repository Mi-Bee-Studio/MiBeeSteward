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

// The off-subnet gate: with a known CIDR in the networks table, a sighting
// outside every known subnet is dropped (no device, counter bumped) instead
// of being stamped onto the local network. With no CIDR knowledge at all the
// fallback applies and the sighting lands.
func TestHandle_OffSubnetGate(t *testing.T) {
	ctx := context.Background()

	gated := memoryDB(t)
	seedNetworks(t, gated, [2]string{"lan-62", "192.168.62.0/24"})
	sink := &recSink37{}
	svc := newDiscSvc37(sink, gated)

	svc.handle(ctx, NewHostEvent{IP: "192.168.193.60", Source: "dhcp_leases"})
	require.Empty(t, sink.reports, "off-subnet sighting must not reach the sink")
	var n int
	require.NoError(t, gated.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address = '192.168.193.60'`).Scan(&n))
	require.Zero(t, n, "off-subnet sighting must not create a device")
	require.Equal(t, int64(1), svc.Status().Stats.OffNetworkDropped)
	require.Equal(t, "skipped_offnetwork", svc.lastEvents[0].Outcome)

	// No CIDR rows anywhere: the gate stays open and the fallback applies.
	open := memoryDB(t)
	seedNetworks(t, open, [2]string{"blank", ""})
	svc2 := newDiscSvc37(sink, open)
	svc2.handle(ctx, NewHostEvent{IP: "192.168.193.60", Source: "dhcp_leases"})
	require.Len(t, sink.reports, 1, "unconfigured geometry keeps the fallback path")
	require.Equal(t, int64(0), svc2.Status().Stats.OffNetworkDropped)
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

// A MAC-only event (WiFi association from hostapd) enriches a known device's
// scan_attributes with the WiFi telemetry and never touches its IP or the
// device bridge; an unknown MAC creates no device.
func TestHandle_MACOnlyEnrich(t *testing.T) {
	ctx := context.Background()
	conn := memoryDB(t)

	sink := &recSink37{}
	svc := newDiscSvc37(sink, conn)

	_, err := conn.Exec(`INSERT INTO devices (name, ip_address, mac_address, status, device_uuid)
		VALUES ('phone', '10.0.0.31', 'aa:bb:cc:dd:ee:31', 'online', 'seed-mac31')`)
	require.NoError(t, err)

	svc.handle(ctx, NewHostEvent{MAC: "aa:bb:cc:dd:ee:31", Source: "hostapd",
		Hints: map[string]string{"wifi_signal_dbm": "-52", "wifi_ssid": "home"}})
	require.Empty(t, sink.reports, "MAC-only events never reach the device bridge")

	var attrs, ip string
	require.NoError(t, conn.QueryRow(
		`SELECT scan_attributes, ip_address FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:31'`).Scan(&attrs, &ip))
	require.Equal(t, "10.0.0.31", ip, "enrich-only must not touch the IP")
	require.Contains(t, attrs, `"signal_dbm":"-52"`)
	require.Contains(t, attrs, `"ssid":"home"`)

	require.Equal(t, int64(1), svc.Status().Stats.MACOnlyEnriched)

	// An unknown MAC is dropped: no device fabricated for a MAC with no L3
	// sighting, and the dedup window suppresses a repeat burst either way.
	svc.handle(ctx, NewHostEvent{MAC: "de:ad:be:ef:00:01", Source: "hostapd"})
	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = 'de:ad:be:ef:00:01'`).Scan(&n))
	require.Zero(t, n)
}
