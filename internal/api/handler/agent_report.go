package handler

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2/runner"
)

// AgentReportHandler receives discovery reports from remote agents
// (POST /api/v1/agents/report). It is the center-side counterpart to the
// agent's reporter: each report is authenticated by RequireAgentToken (which
// binds the request to an agent_id + network_id), and every reported host is
// fed through the runner's device bridge so identity rules (MAC-primary →
// (ip, network_id) fallback) and heartbeat seeding are identical to a local
// scan. This is what makes one center merge portraits from many networks.
type AgentReportHandler struct {
	runner *runner.Runner
}

// NewAgentReportHandler constructs the handler. runner is the center's scan
// runner (reused as-is — applyDeviceBridge takes the agent's network per-call).
func NewAgentReportHandler(rn *runner.Runner) *AgentReportHandler {
	return &AgentReportHandler{runner: rn}
}

// Report handles POST /api/v1/agents/report.
//
// Auth: RequireAgentToken runs before this handler and injects agent_id +
// network_id into the request context. The agent's network_id (from its token)
// is the authoritative origin for every device in the report — NOT a field in
// the JSON body — so a misconfigured or hostile agent can't stamp devices onto
// another network.
func (h *AgentReportHandler) Report(w http.ResponseWriter, r *http.Request) {
	if h.runner == nil {
		Error(w, http.StatusInternalServerError, "scan runner not initialized")
		return
	}
	var rep domain.AgentReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		Error(w, http.StatusBadRequest, "invalid report body")
		return
	}
	if len(rep.Hosts) == 0 {
		// An empty report is valid (an agent may have found nothing alive); ack it.
		Success(w, reportAck{Accepted: 0})
		return
	}

	// The agent's network comes from its token (RequireAgentToken), not the body.
	agentID, networkID, ok := middleware.GetAgentFromContext(r)
	if !ok || networkID == nil {
		// A token without a bound network can't be attributed — reject rather
		// than silently tagging devices with NULL (which would collide with the
		// legacy single-instance pool).
		Error(w, http.StatusForbidden, "agent token has no bound network")
		return
	}
	nid := sql.NullInt64{Int64: *networkID, Valid: true}

	added, updated, skipped := 0, 0, 0
	for _, host := range rep.Hosts {
		if !host.Alive || host.IP == "" {
			skipped++
			continue
		}
		hr := runner.ReportedHostToReport(host)
		isNew, wasUpdated, err := h.runner.ApplyReport(r.Context(), hr, nid, agentID)
		if err != nil {
			slog.Warn("agent report: apply failed", "agent_id", rep.AgentID, "ip", host.IP, "error", err)
			skipped++
			continue
		}
		if isNew {
			added++
		} else if wasUpdated {
			updated++
		}
	}
	slog.Info("agent report received",
		"agent_id", rep.AgentID, "network_id", *networkID,
		"hosts", len(rep.Hosts), "added", added, "updated", updated, "skipped", skipped)

	Success(w, reportAck{Accepted: added + updated, Added: added, Updated: updated, Skipped: skipped})
}

// reportAck is the response to a successful report submission.
type reportAck struct {
	Accepted int `json:"accepted"` // added + updated (hosts the center acted on)
	Added    int `json:"added"`
	Updated  int `json:"updated"`
	Skipped  int `json:"skipped"` // dead hosts, missing IP, or apply errors
}
