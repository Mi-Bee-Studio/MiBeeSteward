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
	"database/sql"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/authz/scoperesolver"
	"mibee-steward/internal/domain"
)

// registerDeviceRoutes registers /api/v1/devices list, stats,
// detail, and write endpoints.
func registerDeviceRoutes(r chi.Router, exportHandler *handler.ExportHandler, deviceHandler *handler.DeviceHandler, batchHandler *handler.BatchHandler, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB) {
	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceRead))
			r.Use(middleware.NetworkScope(scopeResolver))
			r.Get("/export", exportHandler.ExportDevices)
			r.Get("/", deviceHandler.List)
			r.Get("/stats", deviceHandler.GetStats)
			r.With(middleware.ValidateDeviceScope(dbConn)).Get("/{id}", deviceHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceWrite))
			r.Use(middleware.NetworkScope(scopeResolver))
			r.Post("/", deviceHandler.Create)
			r.With(middleware.ValidateDeviceScope(dbConn)).Put("/{id}", deviceHandler.Update)
			r.With(middleware.ValidateDeviceScope(dbConn)).Delete("/{id}", deviceHandler.Delete)
			r.Post("/batch-delete", batchHandler.BatchDeleteDevices)
			r.Post("/batch-update-status", batchHandler.BatchUpdateDeviceStatus)
		})
	})
}

// registerDeviceSystemRoutes registers
// /api/v1/devices/{id}/systems.
func registerDeviceSystemRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, deviceSystemHandler *handler.DeviceSystemHandler) {
	r.Route("/api/v1/devices/{id}/systems", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceRead))
			r.Get("/", deviceSystemHandler.ListByDevice)
			r.Get("/{systemId}", deviceSystemHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceWrite))
			r.Post("/", deviceSystemHandler.Create)
			r.Put("/{systemId}", deviceSystemHandler.Update)
			r.Delete("/{systemId}", deviceSystemHandler.Delete)
		})
	})
}

// registerDeviceNeighborRoutes registers the per-device L2
// neighbor listing.
func registerDeviceNeighborRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, neighborHandler *handler.NeighborHandler) {
	// Device L2 neighbors (Bridge-MIB / LLDP / CDP / ARP), read-only. Feeds
	// the detail-page Neighbors panel.
	r.Route("/api/v1/devices/{id}/neighbors", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapDeviceRead))
		r.Get("/", neighborHandler.ListByDevice)
	})
}

// registerDeviceCertificateRoutes registers the per-device TLS
// certificate listing.
func registerDeviceCertificateRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, tlsCertHandler *handler.TLSCertHandler) {
	// Device TLS certificates (https/ldaps/imaps/etc), read-only. Feeds the
	// detail-page TLS Certificates sub-panel and the per-port certificate Modal
	// (full chain + PEM).
	r.Route("/api/v1/devices/{id}/certificates", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapDeviceRead))
		r.Get("/", tlsCertHandler.ListByDevice)
	})
}

// registerDeviceConfigRoutes registers the per-device
// running-config history.
func registerDeviceConfigRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, deviceConfigHandler *handler.DeviceConfigHandler) {
	// Device running-config history (#137, Oxidized/RANCID-style), read-only.
	// The list omits config_text; the detail + diff views load it on demand.
	// Registered before /{configId} so the static /diff segment wins over the
	// param (chi prefers literal over wildcard).
	r.Route("/api/v1/devices/{id}/configs", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapConfigRead))
		r.Get("/", deviceConfigHandler.List)
		r.Get("/diff", deviceConfigHandler.Diff)
		r.Get("/{configId}", deviceConfigHandler.Get)
	})
}

// registerDocumentRoutes registers /api/v1/documents.
func registerDocumentRoutes(r chi.Router, docHandler *handler.DocumentHandler) {
	r.Route("/api/v1/documents", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentRead))
			r.Get("/", docHandler.List)
			r.Get("/{id}", docHandler.Get)
			r.Get("/{id}/download", docHandler.Download)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentWrite))
			r.Post("/", docHandler.CreateURL)
			r.Post("/upload", docHandler.UploadFile)
			r.Put("/{id}", docHandler.Update)
			r.Delete("/{id}", docHandler.Delete)
			// Undo for the delete-undo toast: restore is a write on the doc.
			r.Post("/{id}/restore", docHandler.Restore)
		})
	})
}

// registerDeviceHeartbeatRoutes registers the heartbeat config,
// results, history, and stats endpoints.
func registerDeviceHeartbeatRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, exportHandler *handler.ExportHandler, heartbeatHandler *handler.HeartbeatHandler) {
	// Device heartbeat configs
	r.Route("/api/v1/devices/{id}/heartbeat-configs", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapHeartbeatRead))
			r.Get("/", heartbeatHandler.ListConfigs)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapHeartbeatManage))
			r.Post("/", heartbeatHandler.CreateConfig)
		})
	})

	// Heartbeat config CRUD
	r.Route("/api/v1/heartbeat-configs", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapHeartbeatManage))
		r.Put("/{id}", heartbeatHandler.UpdateConfig)
		r.Delete("/{id}", heartbeatHandler.DeleteConfig)
	})

	// Heartbeat results
	r.Route("/api/v1/devices/{id}/heartbeat-results", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapHeartbeatRead))
		r.Get("/export", exportHandler.ExportHeartbeatResults)
		r.Get("/", heartbeatHandler.ListResults)
	})

	// Heartbeat history and stats
	r.Group(func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapHeartbeatRead))
		r.Get("/api/v1/devices/{id}/heartbeat-history", heartbeatHandler.ListHistory)
		r.Get("/api/v1/devices/{id}/heartbeat-stats", heartbeatHandler.GetStats)
	})
}

// registerFingerprintRoutes registers the fingerprint coverage
// report and rule-draft endpoints.
func registerFingerprintRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, fingerprintHandler *handler.FingerprintHandler) {
	r.Group(func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.RequireCapability(domain.CapDeviceRead))
		r.Get("/api/v1/fingerprints/coverage", fingerprintHandler.Coverage)
		r.Post("/api/v1/devices/{uuid}/fingerprint-draft", fingerprintHandler.RuleDraft)
	})
}

// registerDeviceDocumentRoutes registers the device-document
// link endpoints.
func registerDeviceDocumentRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, dbConn *sql.DB, linkHandler *handler.LinkHandler) {
	r.Route("/api/v1/devices/{id}/documents", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentRead))
			r.Get("/", linkHandler.GetDeviceDocuments)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentWrite))
			r.Post("/", linkHandler.LinkDocument)
			r.Delete("/{docId}", linkHandler.UnlinkDocument)
		})
	})
	r.Route("/api/v1/documents/{id}/devices", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapDocumentRead))
		r.Get("/", linkHandler.GetDocumentDevices)
	})
}
