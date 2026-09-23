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

// registerAgentTokenRoutes registers /api/v1/agents/tokens.
func registerAgentTokenRoutes(r chi.Router, agentAdminHandler *handler.AgentAdminHandler) {
	r.Route("/api/v1/agents/tokens", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapAgentManage))
		r.Post("/", agentAdminHandler.Create)
		r.Get("/", agentAdminHandler.List)
		r.Post("/{id}/revoke", agentAdminHandler.Revoke)
		r.Delete("/{id}", agentAdminHandler.Delete)
	})
}

// registerAgentRoutes registers the agent report and
// command-channel endpoints under /api/v1/agents.
func registerAgentRoutes(r chi.Router, agentReportHandler *handler.AgentReportHandler, agentProbeReportHandler *handler.AgentProbeReportHandler, agentCommandHandler *handler.AgentCommandHandler) {
	r.Route("/api/v1/agents", func(r chi.Router) {
		r.Use(middleware.RequireAgentToken)
		r.Post("/report", agentReportHandler.Report)
		r.Post("/probe-report", agentProbeReportHandler.Report)
		// Agent command channel (Phase 5c): the agent polls pending commands
		// (GET /commands), acknowledges (POST /commands/{id}/ack), executes, and
		// reports the result (POST /commands/{id}/complete). Pull model.
		r.Get("/commands", agentCommandHandler.Poll)
		r.Post("/commands/{id}/ack", agentCommandHandler.Ack)
		r.Post("/commands/{id}/complete", agentCommandHandler.Complete)
	})
}

// registerAgentCommandAdminRoutes registers the admin-side agent
// command enqueue and fleet status endpoints.
func registerAgentCommandAdminRoutes(r chi.Router, agentCommandHandler *handler.AgentCommandHandler) {
	// Admin-side command management: enqueue a command for an agent (POST) +
	// view all commands (GET). Separate route group (CapAgentManage, not agent
	// token).
	r.Route("/api/v1/agents/{agentId}/commands", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapAgentManage))
		r.Post("/", agentCommandHandler.Create)
	})
	r.With(middleware.RequireCapability(domain.CapAgentManage)).Get("/api/v1/agents/commands/all", agentCommandHandler.ListAll)
	// Fleet-observability table (#278): version / uptime / clock offset /
	// last-report per agent. CapAgentManage (the agents capability, viewer
	// roles already see device-derived data elsewhere; this is admin-plane
	// fleet telemetry).
	r.With(middleware.RequireCapability(domain.CapAgentManage)).Get("/api/v1/agents/status", agentCommandHandler.FleetStatus)
}
