// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package discovery

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/probe"
)

// recordingSink captures the host reports the event loop hands to the sink.
type recordingSink struct {
	mu     sync.Mutex
	events *[]NewHostEvent
}

func (r *recordingSink) Apply(_ context.Context, rep scannerv2.HostReport) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.events = append(*r.events, NewHostEvent{IP: rep.IP})
	return false
}

// TestARPCacheSource_CIDRFilter pins #292: on a form-C center running on the
// router, /proc/net/arp holds BOTH arms' neighbours. With network.cidr set,
// only in-subnet neighbours are recorded; without/invalid cidr the historical
// unfiltered behavior is kept (warn, pass through) — a config typo must not
// disable a previously working source.
func TestARPCacheSource_CIDRFilter(t *testing.T) {
	var events []NewHostEvent
	sink := &recordingSink{events: &events}
	svc := New(Config{}, sink, nil, nil, 0, nil)
	svc.Start(context.Background())
	t.Cleanup(func() { svc.Stop() })

	entries := []probe.ARPEntry{
		{IP: "192.168.64.241", MAC: "02:11:aa:bb:cc:01"}, // LAN side
		{IP: "192.168.63.1", MAC: "94:83:c4:29:97:3e"},   // WAN side (upstream gateway)
		{IP: "192.168.63.101", MAC: "b8:27:eb:11:22:33"}, // WAN side (lab server)
	}

	// Filtered: cidr set → only LAN-side neighbours emitted. The event loop
	// runs on its own goroutine, so poll briefly for the Apply to land.
	src := NewARPCacheSource("192.168.64.0/24", time.Minute, svc, nil)
	src.sweepWith(entries)
	waitFor(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return len(events) > 0 })
	require.Len(t, events, 1, "WAN-side neighbours must be dropped when network.cidr is set")
	require.Equal(t, "192.168.64.241", events[0].IP)

	// Unfiltered: empty cidr keeps the pre-#292 behavior. Fresh service so the
	// in-loop known-host path can't dedup hosts seen in the phase above.
	events = nil
	sink2 := &recordingSink{events: &events}
	svc2 := New(Config{}, sink2, nil, nil, 0, nil)
	svc2.Start(context.Background())
	t.Cleanup(func() { svc2.Stop() })
	src2 := NewARPCacheSource("", time.Minute, svc2, nil)
	src2.sweepWith(entries)
	waitFor(t, func() bool { sink2.mu.Lock(); defer sink2.mu.Unlock(); return len(events) >= 3 })
	require.Len(t, events, 3, "empty cidr must keep the historical unfiltered behavior")
}

// waitFor polls cond every 10ms up to 2s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
