// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// qualityMetrics exports the egress-quality verdicts (#608). Metrics only:
// the notification wiring was explicitly rejected (the "B" direction), this
// is the Prometheus-native surface for alerting on top of the analyzer.
type qualityMetrics struct {
	verdict *prometheus.GaugeVec
	score   *prometheus.GaugeVec
}

// Shared collectors behind a Once, same doctrine as the probe engine
// metrics: routes tests build many routers against the process default
// registry and a second MustRegister would panic.
var (
	qualityMetricsOnce sync.Once
	qualityShared      *qualityMetrics
)

func newQualityMetrics(reg prometheus.Registerer) *qualityMetrics {
	if reg == nil {
		return nil
	}
	qualityMetricsOnce.Do(func() {
		qualityShared = &qualityMetrics{
			verdict: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "mibee_probe_egress_verdict",
				Help: "Egress-quality verdict per vantage and group (1 on the current verdict label; labels: vantage, group, verdict).",
			}, []string{"vantage", "group", "verdict"}),
			score: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: "mibee_probe_quality_score",
				Help: "Egress-quality score per vantage and group, 0-100 (mean ok-rate, capped when the path is down).",
			}, []string{"vantage", "group"}),
		}
		reg.MustRegister(qualityShared.verdict, qualityShared.score)
	})
	return qualityShared
}

// startQualityLoop re-computes the verdicts on a ticker and refreshes the
// gauges. Reset-per-tick keeps the verdict label set exact (a vantage that
// flipped verdicts must not leave its old series behind).
func (s *QualityService) StartMetricsLoop(ctx context.Context, reg prometheus.Registerer, stop <-chan struct{}) {
	metrics := newQualityMetrics(reg)
	if metrics == nil {
		return
	}
	logger := s.logger
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	refresh := func() {
		report, err := s.Analyze(ctx, s.cfg.WindowMinutes)
		if err != nil {
			logger.Warn("probe quality: metrics refresh failed", "error", err)
			return
		}
		metrics.verdict.Reset()
		metrics.score.Reset()
		for _, g := range report.Groups {
			for _, v := range g.Vantages {
				metrics.verdict.WithLabelValues(v.Vantage, g.Name, v.Verdict).Set(1)
				metrics.score.WithLabelValues(v.Vantage, g.Name).Set(float64(v.Score))
			}
		}
	}
	refresh()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			refresh()
		}
	}
}
