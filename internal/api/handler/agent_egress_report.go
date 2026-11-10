// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/service/probeext"
)

// AgentEgressReportHandler handles POST /api/v1/agents/egress-report (#718):
// the agent-side egress collector's round batches. Agent-token authenticated
// (same regime as /agents/report); the reporting agent's identity overrides
// any vantage the payload claims, an agent can only write its own track.
type AgentEgressReportHandler struct {
	svc *probeext.Service
}

func NewAgentEgressReportHandler(svc *probeext.Service) *AgentEgressReportHandler {
	return &AgentEgressReportHandler{svc: svc}
}

// Report accepts a batch of egress rounds. Malformed batches are a 400; a
// store failure is a 500 with the accepted-so-far count logged.
func (h *AgentEgressReportHandler) Report(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := middleware.GetAgentFromContext(r)
	if !ok || agentID == "" {
		Error(w, http.StatusUnauthorized, "agent identity missing")
		return
	}
	var payload struct {
		Rounds []probeext.AgentEgressRound `json:"rounds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(payload.Rounds) == 0 {
		Success(w, map[string]interface{}{"accepted": 0})
		return
	}
	accepted, err := h.svc.IngestAgentEgress(r.Context(), agentID, payload.Rounds)
	if err != nil {
		slog.Error("agent egress report: ingest failed", "agent_id", agentID, "accepted", accepted, "error", err)
		Error(w, http.StatusInternalServerError, "failed to ingest egress rounds")
		return
	}
	Success(w, map[string]interface{}{"accepted": accepted})
}
