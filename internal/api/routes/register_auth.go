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

// registerAuthRoutes registers /api/v1/auth: login routes plus 2FA
// verify and the protected 2FA setup endpoints.
func registerAuthRoutes(r chi.Router, loginLimiter *middleware.RateLimiter, userHandler *handler.UserHandler, totpHandler *handler.TOTPHandler) {
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Use(loginLimiter.Middleware)
		r.Mount("/", userHandler.Routes())
		// 2FA routes (public verify + protected setup/enable/disable/status)
		r.Route("/2fa", func(r chi.Router) {
			r.Post("/verify", totpHandler.Verify)
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAuth)
				r.Post("/setup", totpHandler.Setup)
				r.Post("/enable", totpHandler.Enable)
				r.Post("/disable", totpHandler.Disable)
				r.Get("/status", totpHandler.Status)
			})
		})
	})
}

// registerUserRoutes registers /api/v1/users and
// /api/v1/network-grants.
func registerUserRoutes(r chi.Router, userHandler *handler.UserHandler, batchHandler *handler.BatchHandler, networkGrantHandler *handler.NetworkGrantHandler) {
	// User management, admin-only (#138 CapUserManage; admin is the only role
	// that holds it, so this preserves the prior RequireAdmin semantics while
	// expressing the gate through the capability matrix).
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapUserManage))
		r.Get("/", userHandler.ListUsers)
		r.Post("/batch-delete", batchHandler.BatchDeleteUsers)
		r.Post("/{id}/reset-password", userHandler.AdminResetPassword)
		// Per-user network grants (#138 Phase 3), list the networks a user is
		// scoped to (closed mode). The create/delete surface is /network-grants.
		r.Get("/{id}/network-grants", networkGrantHandler.ListByUser)
	})

	r.Route("/api/v1/network-grants", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapUserManage))
		r.Get("/", networkGrantHandler.List)
		r.Post("/", networkGrantHandler.Create)
		r.Delete("/{id}", networkGrantHandler.Delete)
	})
}

// registerSettingsRoutes registers /api/v1/settings plus the
// read-only /api/v1/system endpoint.
func registerSettingsRoutes(r chi.Router, settingsHandler *handler.SettingsHandler) {
	r.Route("/api/v1/settings", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapUserManage))
		r.Get("/auth", settingsHandler.GetAuth)
		r.Put("/auth", settingsHandler.UpdateAuth)
	})
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/api/v1/system", settingsHandler.GetSystem)
	})
}
