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

// registerProbeTargetRoutes registers /api/v1/probe-targets, the
// egress-quality analysis endpoint (#608), and the egress/path extension
// views (#716/#718/#719). autogenHandler may be nil (sweep-now route is then
// simply not registered).
func registerProbeTargetRoutes(r chi.Router, probeTargetHandler *handler.ProbeTargetHandler, probeQualityHandler *handler.ProbeQualityHandler, probeExtHandler *handler.ProbeExtHandler, autogenHandler *handler.AutogenHandler) {
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapProbeRead))
		r.Get("/api/v1/probe-quality", probeQualityHandler.GetQuality)
		r.Get("/api/v1/probe-quality/history", probeQualityHandler.GetQualityHistory)
		r.Get("/api/v1/probe-quality/episodes", probeExtHandler.Episodes)
		r.Get("/api/v1/probe-egress", probeExtHandler.Egress)
		r.Get("/api/v1/probe-paths", probeExtHandler.Paths)
	})
	r.Route("/api/v1/probe-targets", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapProbeRead))
			r.Get("/", probeTargetHandler.ListTargets)
			r.Get("/{id}", probeTargetHandler.GetTarget)
			r.Get("/{id}/results", probeTargetHandler.GetTargetResults)
			r.Get("/{id}/certificates", probeTargetHandler.GetTargetCertificates)
			r.Get("/{id}/paths", probeExtHandler.TargetPaths)
			r.Get("/{id}/phases", probeExtHandler.TargetPhases)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapProbeManage))
			r.Post("/", probeTargetHandler.CreateTarget)
			r.Put("/{id}", probeTargetHandler.UpdateTarget)
			r.Delete("/{id}", probeTargetHandler.DeleteTarget)
			r.Post("/{id}/trigger", probeTargetHandler.TriggerTarget)
			r.Post("/{id}/trace", probeExtHandler.TraceNow)
			// On-demand autogen reconcile (设置 → 拨测 / probes page LAN
			// empty state): run one sweep now instead of waiting for the
			// periodic tick. Reads the effective (overlay ?? config) policy.
			if autogenHandler != nil {
				r.Post("/autogen-sweep", autogenHandler.SweepNow)
			}
		})
	})
}
