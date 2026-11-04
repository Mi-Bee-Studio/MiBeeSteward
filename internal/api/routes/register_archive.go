// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package routes

import (
	"database/sql"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/authz/scoperesolver"
	"mibee-steward/internal/domain"
)

// registerArchiveRoutes registers the asset-archive surface (#666/#667):
// the archive list + dossier are read-only.
func registerArchiveRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, archiveHandler *handler.ArchiveHandler) {
	r.Route("/api/v1/archive", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapDeviceRead))
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Get("/", archiveHandler.List)
		r.Get("/{id}/dossier", archiveHandler.Dossier)
	})
}

// registerArchiveActionRoutes registers the per-device archive actions
// (#663 manual ops). Fence order mirrors the other device writes: scope,
// then reject remote-network hand edits.
func registerArchiveActionRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, archiveHandler *handler.ArchiveHandler) {
	r.Group(func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapDeviceWrite))
		r.Use(middleware.RejectRemoteNetworkWrite(dbConn))
		r.Post("/api/v1/devices/{id}/archive", archiveHandler.ArchiveDevice)
		r.Post("/api/v1/devices/{id}/restore", archiveHandler.RestoreDevice)
		r.Put("/api/v1/devices/{id}/archive-settings", archiveHandler.PutArchiveSettings)
	})
}

// registerTagRoutes registers the tag dictionary + assignment surface
// (#665). Dictionary reads are available to every authenticated user (the
// edit modal + filters need them); dictionary writes are admin-only
// (CapUserManage, the admin-gating convention).
func registerTagRoutes(r chi.Router, tagHandler *handler.TagHandler) {
	r.Route("/api/v1/tags", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceRead))
			r.Get("/", tagHandler.List)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapUserManage))
			r.Post("/", tagHandler.Create)
			r.Put("/{id}", tagHandler.Update)
			r.Delete("/{id}", tagHandler.Delete)
		})
		// Bulk assign sits between the two: a dictionary-context call that
		// writes many devices at once — needs BOTH caps.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceWrite))
			r.Use(middleware.RequireCapability(domain.CapUserManage))
			r.Post("/{id}/devices", tagHandler.BulkAssign)
		})
	})
}

// registerDeviceTagRoutes registers the per-device tag endpoints
// (read = device read; write = device write, fenced like other edits).
func registerDeviceTagRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, tagHandler *handler.TagHandler) {
	r.Route("/api/v1/devices/{id}/tags", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceRead))
			r.Get("/", tagHandler.ListDeviceTags)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceWrite))
			r.Use(middleware.RejectRemoteNetworkWrite(dbConn))
			r.Put("/", tagHandler.ReplaceDeviceTags)
		})
	})
}
