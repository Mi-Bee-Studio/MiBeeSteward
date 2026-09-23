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

// registerAuditLogRoutes registers /api/v1/audit-logs.
func registerAuditLogRoutes(r chi.Router, auditHandler *handler.AuditHandler, exportHandler *handler.ExportHandler) {
	// Audit log routes, CapAuditRead. The capability matrix (#217) grants
	// audit:read to every read-capable role (admin/operator/viewer/+legacy user):
	// in a CMDB/monitoring tool a read-only stakeholder seeing the "who changed
	// what when" trail is reasonable transparency (cf. NetBox change-logs). This
	// widens the prior admin-only read to viewer+; if a future deployment needs
	// stricter audit visibility, gate on CapAuditManage (admin-only) instead.
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapAuditRead))
		r.Get("/api/v1/audit-logs", auditHandler.List)
		r.Get("/api/v1/audit-logs/facets", auditHandler.Facets)
		r.Get("/api/v1/audit-logs/export", exportHandler.ExportAuditLogs)
	})
}
