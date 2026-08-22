// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// AgentCommandHandler serves both halves of the center→agent command channel:
//   - Admin POST /api/v1/agents/{agentId}/commands — enqueue a command for an agent.
//   - Agent GET /api/v1/agents/commands — poll pending commands (RequireAgentToken).
//   - Agent POST /api/v1/agents/commands/{id}/complete — report a command's result.
//
// This is the pull model: the agent fetches commands on its report cycle, so no
// inbound connection from the center is needed (fits agent-behind-NAT).
// Mutations go through service.AgentCommandService (#240 — charter debt
// migration, including the scan-target network-boundary check); Poll/ListAll
// are read passthroughs.
type AgentCommandHandler struct {
	queries   *db.Queries
	svc       *service.AgentCommandService
	auditRepo *service.AuditRepository
}

// NewAgentCommandHandler constructs the handler. auditRepo records ops-command
// enqueues (#278) — restart/config-reload/logs-tail are privileged actions and
// get an audit trail even when the agent later refuses them.
func NewAgentCommandHandler(queries *db.Queries, svc *service.AgentCommandService, auditRepo *service.AuditRepository) *AgentCommandHandler {
	return &AgentCommandHandler{queries: queries, svc: svc, auditRepo: auditRepo}
}

// Create handles POST /api/v1/agents/{agentId}/commands — admin enqueues a
// command (currently "scan") for a specific agent. The agent picks it up on its
// next poll. The network-boundary rejection for scan commands (issue #19,
// Layer 1) is enforced by the service; its error message (with the offending
// IPs) is surfaced verbatim as the 400 body.
func (h *AgentCommandHandler) Create(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		Error(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	var req struct {
		Command string                 `json:"command"`
		Payload map[string]interface{} `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	row, err := h.svc.Enqueue(r.Context(), agentID, req.Command, req.Payload)
	if err != nil {
		var boundary *service.BoundaryError
		switch {
		case errors.Is(err, service.ErrAgentIDRequired),
			errors.Is(err, service.ErrUnknownCommand),
			errors.As(err, &boundary):
			Error(w, http.StatusBadRequest, err.Error())
			return
		case errors.Is(err, service.ErrRemoteOpsDisabled):
			Error(w, http.StatusForbidden, err.Error())
			return
		default:
			Error(w, http.StatusInternalServerError, "failed to create agent command")
			return
		}
	}
	// Ops commands are privileged: audit every successful enqueue (#278). The
	// agent-side opt-in may still refuse execution — that outcome is visible
	// in the command row's result, this entry records WHO issued it.
	if service.IsOpsCommand(row.Command) && h.auditRepo != nil {
		if userID, _, ok := middleware.GetUserFromContext(r); ok {
			h.auditRepo.Log(r.Context(), service.AuditLog{
				UserID:       &userID,
				Action:       "agent.ops_command",
				ResourceType: "agent",
				ResourceID:   agentID,
				IPAddress:    r.RemoteAddr,
				UserAgent:    r.UserAgent(),
				Details:      "command=" + row.Command,
			})
		}
	}
	Created(w, row)
}

// Poll handles GET /api/v1/agents/commands — the authenticated agent fetches
// its pending commands (status=pending), oldest first. This is the agent-side
// pull. The agent should acknowledge each via POST /commands/{id}/ack, execute,
// then POST /commands/{id}/complete.
func (h *AgentCommandHandler) Poll(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := middleware.GetAgentFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "agent auth required")
		return
	}
	cmds, err := h.queries.ListPendingAgentCommands(r.Context(), db.ListPendingAgentCommandsParams{
		AgentID: agentID,
		Limit:   10,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to poll commands")
		return
	}
	Success(w, cmds)
}

// Ack handles POST /api/v1/agents/commands/{id}/ack — agent acknowledges it
// picked up a command (transitions pending→acknowledged so it isn't re-polled).
func (h *AgentCommandHandler) Ack(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid command id")
		return
	}
	if err := h.svc.Ack(r.Context(), id); err != nil {
		Error(w, http.StatusInternalServerError, "failed to ack command")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Complete handles POST /api/v1/agents/commands/{id}/complete — agent reports
// the result of a finished command (success or failure).
func (h *AgentCommandHandler) Complete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid command id")
		return
	}
	var req struct {
		Status string `json:"status"` // "done" or "failed"
		Result string `json:"result"` // optional JSON detail
	}
	// Empty body is allowed (defaults to status="done"); a malformed body is
	// NOT — silently defaulting would record a broken agent payload as a
	// successful completion, hiding the real outcome (#130).
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		slog.Warn("agent command complete: malformed body", "command_id", id, "error", err)
		Error(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if err := h.svc.Complete(r.Context(), id, req.Status, req.Result); err != nil {
		Error(w, http.StatusInternalServerError, "failed to complete command")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListAll handles GET /api/v1/agents/commands/all — admin view of all commands
// across all agents (for the management UI).
func (h *AgentCommandHandler) ListAll(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	cmds, err := h.queries.ListAllAgentCommands(r.Context(), db.ListAllAgentCommandsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list commands")
		return
	}
	total, err := h.queries.CountAgentCommands(r.Context())
	if err != nil {
		total = 0
	}
	Success(w, domain.AgentCommandListResponse{Commands: cmds, Total: int(total)})
}

// FleetStatus handles GET /api/v1/agents/status — the fleet-observability
// table (#278): one row per agent that has ever reported, with version,
// uptime, clock offset, scans shipped, and last-report time (stalest first).
func (h *AgentCommandHandler) FleetStatus(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.ListAgentStatus(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list agent status")
		return
	}
	Success(w, map[string]any{"agents": rows, "total": len(rows)})
}
