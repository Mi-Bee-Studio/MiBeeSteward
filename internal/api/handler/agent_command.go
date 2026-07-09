package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// AgentCommandHandler serves both halves of the center→agent command channel:
//   - Admin POST /api/v1/agents/{agentId}/commands — enqueue a command for an agent.
//   - Agent GET /api/v1/agents/commands — poll pending commands (RequireAgentToken).
//   - Agent POST /api/v1/agents/commands/{id}/complete — report a command's result.
//
// This is the pull model: the agent fetches commands on its report cycle, so no
// inbound connection from the center is needed (fits agent-behind-NAT).
type AgentCommandHandler struct {
	queries *db.Queries
}

// NewAgentCommandHandler constructs the handler.
func NewAgentCommandHandler(queries *db.Queries) *AgentCommandHandler {
	return &AgentCommandHandler{queries: queries}
}

// Create handles POST /api/v1/agents/{agentId}/commands — admin enqueues a
// command (currently "scan") for a specific agent. The agent picks it up on its
// next poll.
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
	if req.Command == "" {
		req.Command = "scan"
	}
	payloadBytes, _ := json.Marshal(req.Payload)
	row, err := h.queries.CreateAgentCommand(r.Context(), db.CreateAgentCommandParams{
		AgentID: agentID,
		Command: req.Command,
		Payload: string(payloadBytes),
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to create agent command")
		return
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
	if err := h.queries.AckAgentCommand(r.Context(), id); err != nil {
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
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Status != "done" && req.Status != "failed" {
		req.Status = "done"
	}
	if err := h.queries.CompleteAgentCommand(r.Context(), db.CompleteAgentCommandParams{
		Status: req.Status,
		Result: &req.Result,
		ID:     id,
	}); err != nil {
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
