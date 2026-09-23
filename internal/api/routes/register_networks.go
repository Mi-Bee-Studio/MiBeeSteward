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

// registerNetworkRoutes registers /api/v1/networks.
func registerNetworkRoutes(r chi.Router, networkHandler *handler.NetworkHandler) {
	r.Route("/api/v1/networks", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapNetworkRead))
		r.Get("/", networkHandler.List)
		r.Get("/{id}", networkHandler.Get)
		r.Get("/{id}/vlans", networkHandler.VLANs)
		r.With(middleware.RequireCapability(domain.CapNetworkManage)).Post("/", networkHandler.Create)
		r.With(middleware.RequireCapability(domain.CapNetworkManage)).Put("/{id}", networkHandler.Update)
		r.With(middleware.RequireCapability(domain.CapNetworkManage)).Delete("/{id}", networkHandler.Delete)
	})
}
