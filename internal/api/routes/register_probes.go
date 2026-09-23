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
)

// registerProbeTargetRoutes registers /api/v1/probe-targets.
func registerProbeTargetRoutes(r chi.Router, probeTargetHandler *handler.ProbeTargetHandler) {
	r.Route("/api/v1/probe-targets", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapProbeRead))
			r.Get("/", probeTargetHandler.ListTargets)
			r.Get("/{id}", probeTargetHandler.GetTarget)
			r.Get("/{id}/results", probeTargetHandler.GetTargetResults)
			r.Get("/{id}/certificates", probeTargetHandler.GetTargetCertificates)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapProbeManage))
			r.Post("/", probeTargetHandler.CreateTarget)
			r.Put("/{id}", probeTargetHandler.UpdateTarget)
			r.Delete("/{id}", probeTargetHandler.DeleteTarget)
			r.Post("/{id}/trigger", probeTargetHandler.TriggerTarget)
		})
	})
}
