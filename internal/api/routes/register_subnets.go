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

// registerSubnetRoutes registers GET /api/v1/subnets (#503): the subnets
// table scan finalizes keep writing (CIDR + gateway + VLAN linkage), exposed
// read-only. Same capability and scoping posture as the networks family.
func registerSubnetRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, subnetHandler *handler.SubnetHandler) {
	r.Route("/api/v1/subnets", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapNetworkRead))
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Get("/", subnetHandler.List)
	})
}
