// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"mibee-steward/internal/db"
	"mibee-steward/internal/metrics"
)

// The Prometheus collectors themselves live in internal/metrics (neutral
// package) so the service layer can increment them without an
// handler→service→handler import cycle (#238). These aliases keep the
// historical handler.Mibee* references working.

// MetricsHandler returns an http.Handler that serves Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// UpdateDeviceMetrics queries the database and updates the MibeeDevicesTotal gauge.
func UpdateDeviceMetrics(ctx context.Context, dbtx db.DBTX) {
	q := db.New(dbtx)

	statuses, err := q.CountByStatus(ctx)
	if err != nil {
		return
	}

	// Reset all device gauges before setting new values to handle
	// label combinations that no longer exist.
	metrics.MibeeDevicesTotal.Reset()

	for _, s := range statuses {
		metrics.MibeeDevicesTotal.WithLabelValues(s.Status, "").Set(float64(s.Count))
	}
}
