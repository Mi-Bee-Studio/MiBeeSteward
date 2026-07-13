package handler

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/runner"
)

// AgentReportHandler receives discovery reports from remote agents
// (POST /api/v1/agents/report). It is the center-side counterpart to the
// agent's reporter: each report is authenticated by RequireAgentToken (which
// binds the request to an agent_id + network_id), and every reported host is
// fed through the runner's device bridge so identity rules (MAC-primary →
// (ip, network_id) fallback) and heartbeat seeding are identical to a local
// scan. This is what makes one center merge portraits from many networks.
//
// Anti-entropy: agents send an X-Network-State-Hash header (a digest of the
// alive set). When the hash matches the last one seen for this agent's
// network, the network is unchanged and the handler skips the expensive
// per-host device bridge — it only refreshes leases (RecordAliveSnapshots) so
// the lease sweeper's staleness clock keeps ticking. Lost detection for agent
// networks is handled by the background LeaseSweeper, NOT per-report (the old
// DetectLost call was O(whole network) on every POST).
type AgentReportHandler struct {
	runner *runner.Runner

	hashMu     sync.Mutex
	lastHash   map[int64]string    // network_id → most-recent state hash
	lastHashAt map[int64]time.Time // network_id → when that hash was first seen
}

// NewAgentReportHandler constructs the handler. runner is the center's scan
// runner (reused as-is — applyDeviceBridge takes the agent's network per-call).
func NewAgentReportHandler(rn *runner.Runner) *AgentReportHandler {
	return &AgentReportHandler{
		runner:     rn,
		lastHash:   make(map[int64]string),
		lastHashAt: make(map[int64]time.Time),
	}
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

	if len(rep.Hosts) == 0 {
		// An empty report is valid (an agent may have found nothing alive); ack it.
		Success(w, reportAck{Accepted: 0})
		return
	}

	// Anti-entropy: when the agent's state hash matches the last one we saw for
	// this network, the alive set is unchanged. Skip the per-host device bridge
	// entirely and only refresh leases (cheap, indexed upserts) so the lease
	// sweeper's staleness clock keeps ticking. This is the steady-state fast
	// path: most scan cycles on a stable network change nothing.
	stateHash := r.Header.Get("X-Network-State-Hash")
	if stateHash != "" {
		h.hashMu.Lock()
		prev := h.lastHash[*networkID]
		h.hashMu.Unlock()
		if prev == stateHash {
			h.runner.RecordAliveSnapshots(r.Context(), nid, 0, hostReportsForLease(rep.Hosts))
			slog.Debug("agent report: stable network, skipped device bridge",
				"agent_id", rep.AgentID, "network_id", *networkID, "hosts", len(rep.Hosts))
			Success(w, reportAck{Accepted: 0, Stable: true})
			return
		}
	}

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
	// Refresh leases for the alive set (resets miss_count, stamps last_seen_at).
	// Lost detection for agent networks is NO LONGER done per-report (the old
	// DetectLost call was O(whole network) each time) — the background
	// LeaseSweeper expires stale agent devices on its own slow ticker.
	h.runner.RecordAliveSnapshots(r.Context(), nid, 0, hostReportsForLease(rep.Hosts))

	// Cache the hash so the next report can short-circuit if nothing changed.
	if stateHash != "" {
		h.hashMu.Lock()
		h.lastHash[*networkID] = stateHash
		if h.lastHashAt[*networkID].IsZero() {
			h.lastHashAt[*networkID] = time.Now().UTC()
		}
		h.hashMu.Unlock()
	}

	slog.Info("agent report received",
		"agent_id", rep.AgentID, "network_id", *networkID,
		"hosts", len(rep.Hosts), "added", added, "updated", updated, "skipped", skipped)

	Success(w, reportAck{Accepted: added + updated, Added: added, Updated: updated, Skipped: skipped})
}

// hostReportsForLease converts ReportedHosts to the HostReport slice
// RecordAliveSnapshots expects. Only the IP/Alive/MAC fields matter for lease
// refresh (the snapshot upsert keys on (network_id, ip)), so the lightweight
// conversion in ReportedHostToReport is sufficient.
func hostReportsForLease(hosts []domain.ReportedHost) []scannerv2.HostReport {
	out := make([]scannerv2.HostReport, 0, len(hosts))
	for _, host := range hosts {
		if !host.Alive || host.IP == "" {
			continue
		}
		out = append(out, runner.ReportedHostToReport(host))
	}
	return out
}

// reportAck is the response to a successful report submission.
type reportAck struct {
	Accepted int  `json:"accepted"` // added + updated (hosts the center acted on)
	Added    int  `json:"added"`
	Updated  int  `json:"updated"`
	Skipped  int  `json:"skipped"` // dead hosts, missing IP, or apply errors
	Stable   bool `json:"stable"`  // true = state hash matched, device bridge skipped
}
