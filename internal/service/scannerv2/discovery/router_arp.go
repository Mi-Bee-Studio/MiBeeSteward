// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"mibee-steward/internal/service/scannerv2/probe"
)

// tableReader returns the merged ip→mac table from all configured routers.
// It's a function field so tests can inject a synthetic table without real SNMP.
// The default is walkRouters (defined below).
type tableReader func(ctx context.Context, routers []string, community string, timeout time.Duration) map[string]string

// walkRouters is the production tableReader: walks each router's SNMP ARP table
// and merges the results. Failures on one router are tolerated (logged at debug).
func walkRouters(ctx context.Context, routers []string, community string, timeout time.Duration) map[string]string {
	current := map[string]string{}
	for _, r := range routers {
		table := probe.WalkRouterARPTable(ctx, r, community, timeout)
		if table == nil {
			continue
		}
		for ip, mac := range table {
			current[ip] = mac
		}
	}
	return current
}

// RouterARPSource periodically walks one or more routers' SNMP ARP tables
// (ipNetToMediaPhysAddress) and emits a NewHostEvent for every IP+MAC it
// sees. Because a gateway knows every host that has spoken through it, this is
// the widest-coverage discovery source — and its footprint is O(routers), not
// O(hosts): one SNMP Walk per router per interval, touching zero end hosts.
//
// It diffs against the previous snapshot so only newly-seen IPs are emitted;
// a stable network produces no events after the first sweep.
type RouterARPSource struct {
	routers   []string
	community string
	timeout   time.Duration
	interval  time.Duration
	svc       *Service
	logger    *slog.Logger
	readTable tableReader

	mu       sync.Mutex
	previous map[string]string // ip → mac, last sweep
}

// NewRouterARPSource constructs the source. routers/community/timeout mirror
// scanner.router_arp; interval is the poll cadence (typically 60s).
func NewRouterARPSource(routers []string, community string, timeout, interval time.Duration, svc *Service, logger *slog.Logger) *RouterARPSource {
	if logger == nil {
		logger = slog.Default()
	}
	if community == "" {
		community = "public"
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &RouterARPSource{
		routers:   routers,
		community: community,
		timeout:   timeout,
		interval:  interval,
		svc:       svc,
		logger:    logger,
		readTable: walkRouters,
		previous:  map[string]string{},
	}
}

// Start launches the poll goroutine. It does an immediate first sweep (so a
// freshly-started instance seeds its snapshot without waiting an interval) then
// ticks. Idempotent via the ctx lifecycle — cancel ctx to stop.
func (s *RouterARPSource) Start(ctx context.Context) {
	if len(s.routers) == 0 {
		s.logger.Info("discovery: router_arp source idle (no routers configured)")
		return
	}
	go s.loop(ctx)
}

func (s *RouterARPSource) loop(ctx context.Context) {
	// Immediate first sweep so the snapshot is seeded promptly on startup.
	s.sweep(ctx)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep(ctx)
		}
	}
}

// sweep walks every router, merges their tables, diffs against the previous
// snapshot, and emits an event for each newly-seen IP. Failures on a single
// router are logged but don't abort the sweep (a downed router shouldn't mask
// discoveries from another).
func (s *RouterARPSource) sweep(ctx context.Context) {
	current := s.readTable(ctx, s.routers, s.community, s.timeout)
	if len(current) == 0 {
		return
	}

	s.mu.Lock()
	prev := s.previous
	s.previous = current
	s.mu.Unlock()

	// Emit only IPs that weren't in the previous snapshot.
	for ip, mac := range current {
		if _, wasPresent := prev[ip]; wasPresent {
			continue
		}
		s.svc.Emit(NewHostEvent{IP: ip, MAC: mac, Source: "router_arp"})
	}
}

// injectTableForTest swaps in a synthetic table reader and runs one sweep. It
// lets tests drive the diff logic without real SNMP I/O.
func (s *RouterARPSource) injectTableForTest(table map[string]string) {
	s.readTable = func(_ context.Context, _ []string, _ string, _ time.Duration) map[string]string {
		return table
	}
	s.sweep(context.Background())
}
