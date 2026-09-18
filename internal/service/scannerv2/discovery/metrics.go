// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You should use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics wraps the Prometheus counters the discovery coordinator exposes.
// Declared as a struct so a nil receiver disables all metric ops in one check
// (tests and the agent pass a nil registerer to skip registration — the agent
// has no metrics endpoint).
type metrics struct {
	// events counts every handled discovery event by source and outcome. On a
	// router-form (form C) center this is the authoritative answer to "where
	// did this device come from": the cross-subnet entry path (multicast vs
	// dhcp_leases vs the cidr-filtered arp_cache/conntrack) is only
	// distinguishable from these counters. The status endpoint shows the same
	// semantics but requires auth and only keeps a 20-event ring.
	events *prometheus.CounterVec
}

// Counter registration is process-global (DefaultRegisterer), and New can be
// called multiple times in one process (tests construct coordinators
// freely). Registering the same collector twice panics, so we register exactly
// once via sync.Once and hand every Service the same CounterVec. A nil
// registerer skips it entirely — the Once still fires on the first non-nil
// caller and binds the vec to that registerer (same trade-off as
// reconcile/metrics.go).
var (
	eventsCounterOnce sync.Once
	eventsCounter     *prometheus.CounterVec
)

func newMetrics(r prometheus.Registerer) *metrics {
	if r == nil {
		return nil
	}
	eventsCounterOnce.Do(func() {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mibee",
			Subsystem: "discovery",
			Name:      "events_total",
			Help: "Passive-discovery events processed, by source (arp_cache/dhcp_leases/mdns/ssdp/router_arp/…) " +
				"and outcome (recorded/skipped_recent/skipped_known/identify_failed). " +
				"Answers 'where did this device come from' without auth (the status endpoint needs it).",
		}, []string{"source", "outcome"})
		r.MustRegister(c)
		eventsCounter = c
	})
	return &metrics{events: eventsCounter}
}

// recordEvent counts one handled event. Called only from the consumer
// goroutine's single chokepoint (Service.recordEvent), so counter semantics
// stay in lockstep with the status endpoint's ring and the statsSnapshot
// counters — the three views of the same decision points.
func (m *metrics) recordEvent(source, outcome string) {
	if m == nil {
		return
	}
	m.events.WithLabelValues(source, outcome).Inc()
}
