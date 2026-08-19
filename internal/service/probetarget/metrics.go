// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package probetarget implements synthetic probing (拨测): user-configured
// targets (typically external/internet endpoints) probed on fixed intervals,
// blackbox_exporter-style. The tls module — and the https flavor of the http
// module — reuses the scanner's CollectCertChain for full certificate-chain
// collection, extending that internal-network capability to external hosts.
//
// Layout:
//   - service.go   — CRUD (probe_targets) + result history
//   - engine.go    — interval scheduler + persistence of outcomes
//   - executor.go  — per-module probe dispatch (probers + cert collection)
//   - metrics.go   — mibee_probe_* Prometheus collectors
package probetarget

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics wraps the Prometheus collectors the engine exposes on the public
// /metrics endpoint (the blackbox-style consumption path: alert on
// mibee_probe_up / cert expiry from Prometheus, not from MiBee itself).
// A nil receiver disables all metric ops (tests pass a nil registerer).
type metrics struct {
	up         *prometheus.GaugeVec   // mibee_probe_up{name,module}: 1/0
	duration   *prometheus.GaugeVec   // mibee_probe_duration_seconds{name,module}
	certExpiry *prometheus.GaugeVec   // mibee_probe_cert_expiry_timestamp_seconds{name,module}
	checks     *prometheus.CounterVec // mibee_probe_checks_total{status,module}

	// seen tracks the gauge label pairs ever recorded so retain() can prune
	// series of deleted targets (a lingering mibee_probe_up for a target that
	// no longer exists would lie to alerting rules). Counters are cumulative
	// by nature and are NOT pruned.
	mu   sync.Mutex
	seen map[string]labelPair
}

type labelPair struct {
	name   string
	module string
}

// Registration is process-global (DefaultRegisterer) and NewRouter can run
// multiple times in one process (tests). Registering the same collector twice
// panics, so all four collectors register together exactly once; every Engine
// shares them. A nil registerer (tests) skips registration entirely.
var (
	metricsOnce sync.Once
	sharedGa    *probeCollectors
)

type probeCollectors struct {
	up, duration, certExpiry *prometheus.GaugeVec
	checks                   *prometheus.CounterVec
}

func newMetrics(r prometheus.Registerer) *metrics {
	if r == nil {
		return nil
	}
	metricsOnce.Do(func() {
		sharedGa = &probeCollectors{
			up: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: "mibee",
				Subsystem: "probe",
				Name:      "up",
				Help:      "Whether the last probe of this target succeeded (1/0). Mirrors blackbox_exporter's probe_success.",
			}, []string{"name", "module"}),
			duration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: "mibee",
				Subsystem: "probe",
				Name:      "duration_seconds",
				Help:      "Duration of the last probe of this target in seconds.",
			}, []string{"name", "module"}),
			certExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: "mibee",
				Subsystem: "probe",
				Name:      "cert_expiry_timestamp_seconds",
				Help:      "Leaf certificate NotAfter as a Unix timestamp. Mirrors blackbox_exporter's probe_ssl_earliest_cert_expiry; absent when no cert was collected.",
			}, []string{"name", "module"}),
			checks: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "mibee",
				Subsystem: "probe",
				Name:      "checks_total",
				Help:      "Total probe executions by outcome and module.",
			}, []string{"status", "module"}),
		}
		r.MustRegister(sharedGa.up, sharedGa.duration, sharedGa.certExpiry, sharedGa.checks)
	})
	return &metrics{
		up: sharedGa.up, duration: sharedGa.duration,
		certExpiry: sharedGa.certExpiry, checks: sharedGa.checks,
		seen: make(map[string]labelPair),
	}
}

// record sets the current-outcome gauges for one target and bumps the checks
// counter. certExpiryUnix nil = no cert collected this run (the expiry gauge
// series is dropped so stale expiries don't linger).
func (m *metrics) record(name, module, status string, latencySeconds float64, certExpiryUnix *float64) {
	if m == nil {
		return
	}
	up := 0.0
	if status == "success" {
		up = 1.0
	}
	m.up.WithLabelValues(name, module).Set(up)
	m.duration.WithLabelValues(name, module).Set(latencySeconds)
	if certExpiryUnix == nil {
		m.certExpiry.DeleteLabelValues(name, module)
	} else {
		m.certExpiry.WithLabelValues(name, module).Set(*certExpiryUnix)
	}
	m.checks.WithLabelValues(status, module).Inc()

	m.mu.Lock()
	m.seen[name+"/"+module] = labelPair{name: name, module: module}
	m.mu.Unlock()
}

// retain prunes gauge series whose (name,module) is no longer in current —
// targets deleted while this process was running stop being reported instead
// of freezing at their last value.
func (m *metrics) retain(current map[string]bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, p := range m.seen {
		if !current[key] {
			m.up.DeleteLabelValues(p.name, p.module)
			m.duration.DeleteLabelValues(p.name, p.module)
			m.certExpiry.DeleteLabelValues(p.name, p.module)
			delete(m.seen, key)
		}
	}
}
