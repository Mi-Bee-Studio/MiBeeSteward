// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package routes

import (
	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
)

// registerFingerprintAdminRoutes registers /api/v1/fingerprints — the admin
// corpus-management surface (status / upload / rollback / upstream check +
// one-click apply / per-agent corpus adoption). Admin capability gated; the
// machine channel GET /api/v1/agents/fingerprints is a separate route group
// (agent-token auth) registered in register_agents.go.
func registerFingerprintAdminRoutes(r chi.Router, h *handler.FingerprintAdminHandler) {
	r.Route("/api/v1/fingerprints", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapFingerprintManage))
		r.Get("/", h.Get)
		r.Put("/", h.Put)
		// POST alias: browser FormData uploads are POST-shaped (the SPA's
		// api.upload helper included); same handler, same validation pipeline.
		r.Post("/", h.Put)
		r.Post("/rollback", h.Rollback)
		r.Get("/upstream", h.Upstream)
		r.Post("/upstream/apply", h.UpstreamApply)
		r.Get("/agents", h.Agents)
		r.Get("/files/{name}", h.FileContent)
	})
}
