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

// registerChangeRoutes registers /api/v1/changes and the
// /changes/watch SSE endpoint.
func registerChangeRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, changeLogHandler *handler.ChangeLogHandler, changeWatchHandler *handler.ChangeWatchHandler) {
	r.Route("/api/v1/changes", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapChangesRead))
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Get("/", changeLogHandler.List)
		r.Get("/watch", changeWatchHandler.Watch)
	})
}
