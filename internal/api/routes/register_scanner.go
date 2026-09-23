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

// registerScannerRoutes registers /api/v1/scanner: sync scan,
// tasks, runs, and results.
func registerScannerRoutes(r chi.Router, scopeResolver *scoperesolver.Resolver, scanLimiter *middleware.ScanRateLimiter, scannerHandler *handler.ScannerHandler, scannerTaskHandler *handler.ScannerTaskHandler, scannerResultHandler *handler.ScannerResultHandler) {
	r.Route("/api/v1/scanner", func(r chi.Router) {
		// #138 Phase 1b: scanner routes are gated by capability, not a blanket
		// RequireAdmin. admin inherits every capability (unchanged access); the
		// new operator role gains scan access; viewer gains read-only access to
		// results/tasks/runs (same inventory-data class as the RequireAuth device
		// endpoints). Each tier is its own group so the capability matches the
		// action (reads → discovery:read, triggers → scan:trigger, task CRUD +
		// bulk delete → scan:manage, add-devices → device:write).
		//
		// #138 Phase 2c: the READ surfaces are additionally object-level scoped
		// - a closed-mode non-admin sees only tasks/runs/results whose
		// scan_tasks.network_id is in their granted set (details return 404).
		// Writes (task CRUD/trigger) stay capability-gated only: operators are
		// trusted to aim scans; grants isolate visibility, not operation.
		r.Use(middleware.NetworkScope(scopeResolver))

		// Reads: discovery:read (viewer+). Scan results, task lists, runs.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDiscoveryRead))
			r.Get("/tasks", scannerTaskHandler.ListTasks)
			r.Get("/tasks/{id}", scannerTaskHandler.GetTask)
			r.Get("/tasks/{id}/runs", scannerTaskHandler.GetTaskRuns)
			r.Get("/tasks/{id}/results", scannerTaskHandler.GetTaskResults)
			r.Get("/results", scannerResultHandler.ListResults)
			r.Get("/results/{id}", scannerResultHandler.GetResult)
			r.Get("/runs", scannerResultHandler.ListRuns)
			r.Get("/runs/{id}", scannerResultHandler.GetRun)
			r.Get("/results/export", scannerResultHandler.ExportScanResults)
		})

		// Scan triggers: scan:trigger (operator+). Rate-limited per-IP (these
		// START scans). The rate limiter runs AFTER the capability gate, so a
		// rejected (403) request never consumes a rate token.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapScanTrigger))
			r.Use(scanLimiter.Middleware)
			r.Post("/scan", scannerHandler.Scan)
			r.Post("/tasks/{id}/trigger", scannerTaskHandler.TriggerTask)
		})

		// Cancel a running scan: scan:trigger (operator+), but NOT rate-limited
		// (it stops a run, doesn't start one).
		r.With(middleware.RequireCapability(domain.CapScanTrigger)).
			Post("/tasks/{id}/cancel", scannerTaskHandler.CancelScanTask)

		// Scan task CRUD + bulk result delete: scan:manage (operator+).
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapScanManage))
			r.Post("/tasks", scannerTaskHandler.CreateTask)
			r.Put("/tasks/{id}", scannerTaskHandler.UpdateTask)
			r.Delete("/tasks/{id}", scannerTaskHandler.DeleteTask)
			r.Delete("/results", scannerResultHandler.BulkDeleteResults)
		})

		// Add devices from a scan: device:write (operator+).
		r.With(middleware.RequireCapability(domain.CapDeviceWrite)).
			Post("/add-devices", scannerHandler.AddDevices)
	})
}
