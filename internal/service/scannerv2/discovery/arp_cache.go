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

// ARPCacheSource periodically reads the local kernel ARP cache
// (/proc/net/arp) and emits a NewHostEvent for every newly-resolved neighbour.
// It is the zero-network-traffic source: it inspects only the scanner host's
// own neighbour table, so its coverage is limited to hosts the scanner has
// already communicated with (directly, or via the scheduled full scan's
// ICMP/TCP probes which populate this cache).
//
// It complements RouterARPSource: where the router walk covers the whole subnet
// (including hosts the scanner host never talks to directly), this source is a
// free byproduct of normal operation — no extra packets, just a periodic file
// read + diff.
type ARPCacheSource struct {
	interval time.Duration
	svc      *Service
	logger   *slog.Logger

	mu       sync.Mutex
	previous map[string]string // ip → mac, last sweep
}

// NewARPCacheSource constructs the source. interval is the poll cadence
// (typically 60s, same as RouterARPSource so they stay in lockstep).
func NewARPCacheSource(interval time.Duration, svc *Service, logger *slog.Logger) *ARPCacheSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &ARPCacheSource{
		interval: interval,
		svc:      svc,
		logger:   logger,
		previous: map[string]string{},
	}
}

// Start launches the poll goroutine (immediate first sweep, then ticks).
func (s *ARPCacheSource) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *ARPCacheSource) loop(ctx context.Context) {
	s.sweep()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

// sweep reads /proc/net/arp, diffs against the previous snapshot, and emits an
// event for each newly-resolved IP. A read error (e.g. non-Linux host) is
// logged once-per-call at debug level and otherwise tolerated.
func (s *ARPCacheSource) sweep() {
	entries, err := probe.ReadARPTable()
	if err != nil {
		s.logger.Debug("discovery: arp_cache read failed", "error", err)
		return
	}
	current := make(map[string]string, len(entries))
	for _, e := range entries {
		current[e.IP] = e.MAC
	}

	s.mu.Lock()
	prev := s.previous
	s.previous = current
	s.mu.Unlock()

	for ip, mac := range current {
		if _, wasPresent := prev[ip]; wasPresent {
			continue
		}
		s.svc.Emit(NewHostEvent{IP: ip, MAC: mac, Source: "arp_cache"})
	}
}
