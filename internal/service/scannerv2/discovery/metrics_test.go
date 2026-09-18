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
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetrics_EventsCounterBySourceAndOutcome drives the consumer loop through
// the three main decision points (recorded / skipped_recent / skipped_known)
// and asserts each lands in mibee_discovery_events_total with its
// source+outcome labels — the Prometheus answer to "where did this device
// come from" that previously required the auth-gated status endpoint.
func TestMetrics_EventsCounterBySourceAndOutcome(t *testing.T) {
	dbConn := memoryDB(t)
	if _, err := dbConn.Exec(`INSERT INTO devices (name, ip_address, status) VALUES ('seed', '10.0.0.9', 'online')`); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	reg := prometheus.NewRegistry()
	svc := New(Config{Interval: time.Second, TriggerIdentify: false}, &fakeSink{isNew: true}, nil, dbConn, 0, reg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc.Start(ctx)
	t.Cleanup(svc.Stop)

	// Genuinely-new host → recorded; immediate repeat → skipped_recent;
	// host already in the device DB → skipped_known.
	svc.Emit(NewHostEvent{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:01", Source: "dhcp_leases"})
	svc.Emit(NewHostEvent{IP: "10.0.0.1", Source: "dhcp_leases"})
	svc.Emit(NewHostEvent{IP: "10.0.0.9", Source: "mdns"})

	deadline := time.Now().Add(2 * time.Second)
	for {
		if testutil.ToFloat64(eventsCounter.WithLabelValues("mdns", "skipped_known")) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("consumer did not process the events within 2s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, tc := range []struct {
		source, outcome string
	}{
		{"dhcp_leases", "recorded"},
		{"dhcp_leases", "skipped_recent"},
		{"mdns", "skipped_known"},
	} {
		if got := testutil.ToFloat64(eventsCounter.WithLabelValues(tc.source, tc.outcome)); got != 1 {
			t.Errorf("mibee_discovery_events_total{source=%q,outcome=%q} = %v, want 1", tc.source, tc.outcome, got)
		}
	}
}
