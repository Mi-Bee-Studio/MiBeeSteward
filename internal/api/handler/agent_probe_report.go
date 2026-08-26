// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/service/probetarget"
)

// AgentProbeReportHandler handles POST /api/v1/agents/probe-report (#277):
// the agent-side vantage prober's result batches. Agent-token authenticated
// (same regime as /agents/report); the reporting agent's identity overrides
// any vantage the payload claims — an agent can only write its own track.
type AgentProbeReportHandler struct {
	svc *probetarget.Service
}

func NewAgentProbeReportHandler(svc *probetarget.Service) *AgentProbeReportHandler {
	return &AgentProbeReportHandler{svc: svc}
}

// Report accepts a batch of probe results. Rows for targets deleted between
// plan and report are skipped silently (normal race); malformed batches are
// a 400.
func (h *AgentProbeReportHandler) Report(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := middleware.GetAgentFromContext(r)
	if !ok || agentID == "" {
		Error(w, http.StatusUnauthorized, "agent identity missing")
		return
	}
	var payload struct {
		Results []probetarget.AgentResultReport `json:"results"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(payload.Results) == 0 {
		Success(w, map[string]interface{}{"accepted": 0})
		return
	}
	accepted, err := h.svc.IngestAgentResults(r.Context(), agentID, payload.Results)
	if err != nil {
		slog.Error("agent probe report: ingest failed", "agent_id", agentID, "accepted", accepted, "error", err)
		Error(w, http.StatusInternalServerError, "failed to ingest probe results")
		return
	}
	Success(w, map[string]interface{}{"accepted": accepted})
}
