// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package reconcile

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics wraps the Prometheus gauges the reconciler exposes. Declared as a
// struct so a nil receiver disables all metric ops in one check (tests pass
// nil to skip registration).
type metrics struct {
	// mismatches is the count of devices whose IP falls outside their stamped
	// network's CIDR, per network. A gauge (set per scan, then reset before the
	// next scan) so it reflects the CURRENT drift, not a cumulative tally — a
	// corrected device drops the gauge back toward 0, which is what an operator
	// alerting on it wants to see.
	mismatches *prometheus.GaugeVec
}

// Gauge registration is process-global (DefaultRegisterer), and NewRouter can
// be called multiple times in one process (tests, hot reloads). Registering the
// same collector twice panics, so we register exactly once via sync.Once and
// hand every Service the same GaugeVec. A nil registerer (tests) skips it
// entirely — each Service gets its own throwaway metrics struct.
var (
	mismatchGaugeOnce sync.Once
	mismatchGauge     *prometheus.GaugeVec
)

func newMetrics(r prometheus.Registerer) *metrics {
	if r == nil {
		return nil
	}
	mismatchGaugeOnce.Do(func() {
		g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "mibee",
			Subsystem: "network",
			Name:      "mismatches",
			Help:      "Devices whose IP falls outside their stamped network's CIDR (issue #19 reconciliation). Set per scan; 0 = no drift.",
		}, []string{"network_id", "network"})
		r.MustRegister(g)
		mismatchGauge = g
	})
	return &metrics{mismatches: mismatchGauge}
}

// set records the mismatch count for one network for this scan.
func (m *metrics) set(networkID int64, network string, n int) {
	if m == nil {
		return
	}
	m.mismatches.WithLabelValues(itoa(networkID), network).Set(float64(n))
}

// reset clears all labels so a network that previously had mismatches but no
// longer does returns to 0 (otherwise stale label-sets would linger).
func (m *metrics) reset() {
	if m == nil {
		return
	}
	m.mismatches.Reset()
}

// itoa avoids importing strconv just for this. GaugeVec labels are strings.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
