package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// AgentAdminHandler exposes admin-only CRUD for discovery-agent bearer tokens
// (POST/GET/DELETE /api/v1/agents/tokens). An admin creates one token per
// network/agent and hands the plaintext to the agent operator; the agent then
// presents it to the ingestion endpoints (RequireAgentToken). This handler is
// the management surface; auth verification lives in the middleware.
type AgentAdminHandler struct {
	queries *db.Queries
}

// NewAgentAdminHandler constructs the handler. queries is the center's DB.
func NewAgentAdminHandler(queries *db.Queries) *AgentAdminHandler {
	return &AgentAdminHandler{queries: queries}
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
	if req.AgentID == "" {
		Error(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	if req.NetworkID <= 0 {
		Error(w, http.StatusBadRequest, "network_id is required")
		return
	}
	// Verify the network exists so the foreign key isn't dangling.
	if _, err := h.queries.GetNetwork(r.Context(), req.NetworkID); err != nil {
		Error(w, http.StatusBadRequest, "network_id does not refer to a known network")
		return
	}

	plaintext, hash := middleware.GenerateAgentToken()
	networkIDPtr := req.NetworkID // take address of a stable local
	row, err := h.queries.CreateAgentToken(r.Context(), db.CreateAgentTokenParams{
		AgentID:   req.AgentID,
		TokenHash: hash,
		NetworkID: &networkIDPtr,
		Name:      req.Name,
	})
	if err != nil {
		// UNIQUE(agent_id) collision is the common error here.
		Error(w, http.StatusConflict, "agent_id already exists; choose a unique id")
		return
	}

	// Mark the network as agent-managed: this is the wiring that makes the
	// center's heartbeat exclusion (no cross-subnet probing of agent devices)
	// and the lease sweeper scope engage automatically — without it an admin
	// would have to run manual SQL. Best-effort: a failure here leaves the
	// token functional (reports still work); the network just isn't scoped.
	agentIDStr := req.AgentID
	// Best-effort: a failure here leaves the token functional (reports still
	// work); the network just isn't scoped for heartbeat exclusion. The error
	// is intentionally discarded — see the comment above.
	_ = h.queries.SetNetworkAgentID(r.Context(), db.SetNetworkAgentIDParams{
		AgentID: &agentIDStr,
		ID:      req.NetworkID,
	})

	Created(w, domain.AgentTokenCreatedResponse{
		AgentTokenResponse: domain.AgentTokenResponse{
			ID:         row.ID,
			AgentID:    row.AgentID,
			NetworkID:  row.NetworkID,
			Name:       row.Name,
			CreatedAt:  row.CreatedAt,
			LastUsedAt: row.LastUsedAt,
			RevokedAt:  row.RevokedAt,
		},
		Token: plaintext,
	})
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
	// Fetch the token first so we can clear its network's agent_id after.
	tok, err := h.queries.GetAgentToken(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, "agent token not found")
		return
	}
	n, err := h.queries.RevokeAgentToken(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to revoke agent token")
		return
	}
	if n == 0 {
		Error(w, http.StatusNotFound, "agent token not found or already revoked")
		return
	}
	h.clearNetworkAgentID(r.Context(), tok)
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
	tok, err := h.queries.GetAgentToken(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, "agent token not found")
		return
	}
	n, err := h.queries.DeleteAgentToken(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete agent token")
		return
	}
	if n == 0 {
		Error(w, http.StatusNotFound, "agent token not found")
		return
	}
	h.clearNetworkAgentID(r.Context(), tok)
	w.WriteHeader(http.StatusNoContent)
}

// clearNetworkAgentID nulls out the agent_id on the token's bound network,
// but ONLY if it matches the token's own agent_id (so revoking a stale token
// doesn't clobber a newer token that re-uses the network). Best-effort: a
// failure here doesn't undo the revoke/delete.
func (h *AgentAdminHandler) clearNetworkAgentID(ctx context.Context, tok db.AgentToken) {
	if tok.NetworkID == nil {
		return
	}
	net, err := h.queries.GetNetwork(ctx, *tok.NetworkID)
	if err != nil {
		return
	}
	// Only clear if the network's agent_id matches THIS token's agent_id — a
	// different agent_id means a newer token has since claimed the network.
	if net.AgentID == nil || *net.AgentID != tok.AgentID {
		return
	}
	empty := ""
	_ = h.queries.SetNetworkAgentID(ctx, db.SetNetworkAgentIDParams{
		AgentID: &empty,
		ID:      *tok.NetworkID,
	})
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
