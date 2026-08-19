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
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// AgentAdminHandler exposes admin-only CRUD for discovery-agent bearer tokens
// (POST/GET/DELETE /api/v1/agents/tokens). An admin creates one token per
// network/agent and hands the plaintext to the agent operator; the agent then
// presents it to the ingestion endpoints (RequireAgentToken). Mutations go
// through service.AgentTokenService (#240 — charter debt migration); the
// plaintext is minted here (one-time credential display concern) and injected
// into the service. List is a read passthrough.
type AgentAdminHandler struct {
	queries *db.Queries
	svc     *service.AgentTokenService
}

// NewAgentAdminHandler constructs the handler. queries is the center's DB.
func NewAgentAdminHandler(queries *db.Queries, svc *service.AgentTokenService) *AgentAdminHandler {
	return &AgentAdminHandler{queries: queries, svc: svc}
}

// Create handles POST /api/v1/agents/tokens — mint a new agent token.
// The plaintext is returned ONCE in the response (Token field) and is never
// recoverable; the stored row holds only the hash.
func (h *AgentAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateAgentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.svc.Create(r.Context(), req, middleware.GenerateAgentToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrAgentIDRequired), errors.Is(err, service.ErrNetworkIDInvalid):
			Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, service.ErrAgentIDTaken):
			Error(w, http.StatusConflict, err.Error())
		default:
			Error(w, http.StatusInternalServerError, "failed to create agent token")
		}
		return
	}
	Created(w, resp)
}

// List handles GET /api/v1/agents/tokens — list all agent tokens (hash only,
// never plaintext).
func (h *AgentAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.queries.ListAgentTokens(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list agent tokens")
		return
	}
	out := make([]domain.AgentTokenResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.AgentTokenResponse{
			ID:         row.ID,
			AgentID:    row.AgentID,
			NetworkID:  row.NetworkID,
			Name:       row.Name,
			CreatedAt:  row.CreatedAt,
			LastUsedAt: row.LastUsedAt,
			RevokedAt:  row.RevokedAt,
		})
	}
	Success(w, out)
}

// Revoke handles POST /api/v1/agents/tokens/{id}/revoke — soft-revoke (sets
// revoked_at). The token immediately fails auth. Kept as a soft delete so the
// audit trail (last_used_at, created_at) survives. Also clears the network's
// agent_id so the center resumes local probing (the agent is no longer reporting).
func (h *AgentAdminHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	id, err := parseAgentID(w, r)
	if err != nil {
		return
	}
	if err := h.svc.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, service.ErrAgentTokenNotFound) {
			Error(w, http.StatusNotFound, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to revoke agent token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete handles DELETE /api/v1/agents/tokens/{id} — hard delete. Prefer
// Revoke for auditability; Delete is for cleanup of test/mistake tokens. Also
// clears the network's agent_id.
func (h *AgentAdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := parseAgentID(w, r)
	if err != nil {
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		if errors.Is(err, service.ErrAgentTokenNotFound) {
			Error(w, http.StatusNotFound, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete agent token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseAgentID extracts the {id} path param as a positive int64.
func parseAgentID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid agent token ID")
		return 0, err
	}
	return id, nil
}
