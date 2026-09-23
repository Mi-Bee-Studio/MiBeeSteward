// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package routes

import (
	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
	scannerv2discovery "mibee-steward/internal/service/scannerv2/discovery"
)

// registerDiscoveryRoutes registers /api/v1/discovery/status.
func registerDiscoveryRoutes(r chi.Router, discSvcForStatus *scannerv2discovery.Service) {
	// Passive discovery status: runtime counters (events received, dedup hits,
	// identify triggers, devices recorded) + the last few discovery outcomes +
	// which sources are active. Auth-gated (any logged-in user). Returns
	// enabled=false when discovery is off or the service was never started.
	r.Route("/api/v1/discovery", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapDiscoveryRead))
		r.Get("/status", handler.DiscoveryStatusHandler(discSvcForStatus))
	})
}
