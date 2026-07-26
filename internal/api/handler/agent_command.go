// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/cidrutil"
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
//
// Boundary check (issue #19, Layer 1): for "scan" commands the requested
// targets must fall inside the agent's bound network CIDR. This is the earliest
// interception point and the cheapest defense against cross-subnet mis-dispatch
// — exactly what let agent-62 scan 192.168.63.0/24 and strand 30 devices into
// the wrong network. If the network has no CIDR configured we do NOT reject
// (degrade-open + warn): historical networks may lack cidr, and forcing it
// here would block every existing agent. CIDR enforcement is a separate
// prerequisite (issue #19 前置工作). An out-of-network target is a hard 400 —
// we surface the offending IPs so the admin sees exactly what was rejected
// rather than silently scanning a subset.
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

	// Enforce the network boundary for scan commands. Other command types (none
	// today, but the channel is extensible) skip this — only "scan" carries a
	// targets field that could reach foreign subnets.
	if req.Command == "scan" {
		if bad := validateScanTargets(r.Context(), h.queries, agentID, req.Payload); bad != "" {
			Error(w, http.StatusBadRequest, bad)
			return
		}
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

// validateScanTargets checks that a scan command's targets fall inside the
// agent's bound network. Returns "" when the command is acceptable, or a
// human-readable reason string (to be used as the 400 body) when it must be
// rejected. It never errors out on missing CIDR — that degrades to allow +
// warn so historical networks without cidr aren't locked out (see the Layer 1
// note above and issue #19 前置工作).
func validateScanTargets(ctx context.Context, queries *db.Queries, agentID string, payload map[string]interface{}) string {
	rawTargets, _ := payload["targets"].(string)
	targets := strings.TrimSpace(rawTargets)
	if targets == "" {
		// Missing targets is the agent-command layer's own concern (the poller
		// rejects it as "missing targets"); not a CIDR issue. Let it through.
		return ""
	}
	net, err := queries.GetNetworkByAgentID(ctx, &agentID)
	if err != nil {
		// No network bound to this agent_id (unknown agent, or the network row
		// has no agent_id stamp). We can't validate, so allow + warn rather than
		// hard-failing — the agent itself will reject the command if it can't
		// reach the target. This keeps the boundary check best-effort.
		slog.Warn("agent command: cannot resolve agent network for boundary check; allowing",
			"agent_id", agentID, "error", err)
		return ""
	}
	cidr := ""
	if net.Cidr != nil {
		cidr = *net.Cidr
	}
	ipNet, perr := cidrutil.ParseNetwork(cidr)
	if errors.Is(perr, cidrutil.ErrEmptyCIDR) {
		// Network exists but has no cidr configured — degrade-open + warn.
		// This is the gap the cidr-enforcement prerequisite (issue #19) closes.
		slog.Warn("agent command: agent network has no cidr; boundary check skipped",
			"agent_id", agentID, "network_id", net.ID, "network_name", net.Name)
		return ""
	}
	if perr != nil {
		// A configured-but-unparseable cidr is a data error worth surfacing.
		return "agent network has invalid cidr: " + cidr
	}
	in, out, perr := cidrutil.PartitionTargets(targets, ipNet)
	if perr != nil {
		return "invalid scan targets: " + perr.Error()
	}
	if len(out) > 0 {
		// Hard reject. Surface a sample of the offending IPs (cap to keep the
		// error body readable for large out-of-network CIDRs). Admin sees what
		// was rejected and can re-issue correctly.
		sample := out
		const maxSample = 8
		if len(sample) > maxSample {
			sample = append(append([]string{}, out[:maxSample]...), "...")
		}
		return "scan targets are outside agent network " + net.Name + " (" + cidr + "): " +
			strings.Join(sample, ", ") + " (" + strconv.Itoa(len(out)) + " of " + strconv.Itoa(len(in)+len(out)) + " IPs out of network)"
	}
	return ""
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
