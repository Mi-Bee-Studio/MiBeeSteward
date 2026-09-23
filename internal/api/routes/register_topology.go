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
	"mibee-steward/internal/authz/scoperesolver"
	"mibee-steward/internal/domain"
)

// registerTopologyRoutes registers /api/v1/topology.
func registerTopologyRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, topologyHandler *handler.TopologyHandler) {
	// Network-level topology graph, all devices (nodes) + all neighbor edges.
	// Read-only. Feeds the /topology page.
	r.Route("/api/v1/topology", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapTopologyRead))
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Get("/", topologyHandler.Graph)
	})
}

// registerDashboardRoutes registers /api/v1/dashboard.
func registerDashboardRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dashHandler *handler.DashboardHandler) {
	r.Route("/api/v1/dashboard", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDashboardRead))
			r.Use(middleware.NetworkScope(scopeResolver))
			r.Get("/configs", dashHandler.ListConfigs)
			r.Get("/overview", dashHandler.Overview)
			r.Get("/query", dashHandler.Query)
			r.Get("/query_range", dashHandler.QueryRange)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDashboardManage))
			r.Post("/configs", dashHandler.CreateConfig)
			r.Put("/configs/{id}", dashHandler.UpdateConfig)
			r.Delete("/configs/{id}", dashHandler.DeleteConfig)
		})
	})
}
