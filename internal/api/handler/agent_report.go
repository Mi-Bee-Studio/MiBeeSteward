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
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/cidrutil"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/metrics"
	"mibee-steward/internal/service"
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
	runner  *runner.Runner
	queries *db.Queries // for resolving the agent network's CIDR (boundary check)
	dbConn  *sql.DB     // raw conn for the networks.cidr backfill (sqlc has no single-col UPDATE)
	// fleetSvc records the per-agent status snapshot (#278). May be nil in
	// tests — status recording degrades to a debug log.
	fleetSvc *service.AgentCommandService

	hashMu     sync.Mutex
	lastHash   map[int64]string    // network_id → most-recent state hash
	lastHashAt map[int64]time.Time // network_id → when that hash was first seen

	// cidrCache memoizes the parsed CIDR per network_id so the per-host boundary
	// check doesn't re-query + re-parse on every report (agents report ~30s).
	// A nil entry means "this network has no usable CIDR — skip the check"
	// (degrade-open; see Layer 2 note + issue #19 前置工作). Guards the whole
	// map; reads are cheap (one map lookup), writes rare (network config change).
	cidrMu    sync.RWMutex
	cidrCache map[int64]*net.IPNet
}

// NewAgentReportHandler constructs the handler. runner is the center's scan
// runner (reused as-is — applyDeviceBridge takes the agent's network per-call);
// queries is used to resolve the agent's network CIDR for the per-host boundary
// check (issue #19 Layer 2); dbConn is for the networks.cidr backfill (the
// single-column UPDATE has no sqlc-generated equivalent).
func NewAgentReportHandler(rn *runner.Runner, queries *db.Queries, dbConn *sql.DB, fleetSvc *service.AgentCommandService) *AgentReportHandler {
	return &AgentReportHandler{
		runner:     rn,
		queries:    queries,
		dbConn:     dbConn,
		fleetSvc:   fleetSvc,
		lastHash:   make(map[int64]string),
		lastHashAt: make(map[int64]time.Time),
		cidrCache:  make(map[int64]*net.IPNet),
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

	// Liveness signal for the AgentReportStale alert (#279): stamped on every
	// authenticated report, including empty and anti-entropy fast-path ones.
	metrics.MibeeAgentLastReportTimestamp.WithLabelValues(agentID).SetToCurrentTime()

	// Fleet status snapshot (#278): version/uptime/hostname from the report's
	// meta block, clock offset from ScannedAt vs receive time (includes
	// transit; a CONSISTENT offset across reports is the skew signal). Runs
	// before the empty-report early return so status-only heartbeats land too.
	if h.fleetSvc != nil {
		offset := time.Since(rep.ScannedAt).Seconds()
		const saneRange = 86400 // ±1d clamp: a retried batch's stale ScannedAt must not poison the value
		if offset > saneRange || offset < -saneRange {
			offset = 0
		}
		if err := h.fleetSvc.UpsertAgentStatus(r.Context(), agentID, rep.Meta, offset); err != nil {
			slog.Debug("agent report: fleet status upsert failed", "agent_id", agentID, "error", err)
		}
	}

	// Prerequisite backfill (issue #19 前置工作): if the agent ships its
	// configured CIDR AND the bound network's row lacks one, adopt it. Agent
	// networks are created via the admin API without a cidr today, so without
	// this the Layer 1/2 boundary checks would degrade-open forever for them.
	// Once filled, invalidate the cidr cache so the next resolveNetworkCIDR
	// picks it up. The token still authoritatively binds network_id — this only
	// supplies the cidr geometry the agent knows best (its own LAN).
	if rep.NetworkCIDR != "" {
		h.maybeBackfillNetworkCIDR(r.Context(), *networkID, rep.NetworkCIDR)
	}

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
			// Even on the fast path we apply the boundary check to the lease
			// set: a stable network that happens to contain out-of-network hosts
			// (shouldn't happen post-Layer-1/2, but defensively) must not keep
			// refreshing those foreign leases. resolveNetworkCIDR is cached, so
			// this is one map lookup + per-host Contains — negligible vs. the
			// lease upserts we're already doing.
			hostsForLease, oon := h.filterInNetwork(r.Context(), *networkID, rep.Hosts)
			if oon > 0 {
				slog.Warn("agent report: stable network, dropped out-of-network hosts",
					"agent_id", rep.AgentID, "network_id", *networkID, "out_of_network", oon)
			}
			h.runner.RecordAliveSnapshots(r.Context(), nid, 0, hostReportsForLease(hostsForLease))
			slog.Debug("agent report: stable network, skipped device bridge",
				"agent_id", rep.AgentID, "network_id", *networkID, "hosts", len(rep.Hosts))
			Success(w, reportAck{Accepted: 0, Stable: true, OutOfNetwork: oon})
			return
		}
	}

	added, updated, skipped := 0, 0, 0
	// Count dead / empty-IP hosts as skipped (they're filtered out of the alive
	// set by filterInNetwork's alive+IP guard before the boundary check).
	for _, host := range rep.Hosts {
		if !host.Alive || host.IP == "" {
			skipped++
		}
	}
	// Boundary check (issue #19 Layer 2): see filterInNetwork. Resolve once,
	// then partition. inNetwork feeds BOTH the device bridge (ApplyReport) and
	// the lease refresh — a dropped out-of-network host must not keep its lease
	// fresh, or it would masquerade as alive in the wrong network (the exact
	// issue-#19 failure).
	inNetwork, outOfNetwork := h.filterInNetwork(r.Context(), *networkID, rep.Hosts)
	skipped += outOfNetwork
	if outOfNetwork > 0 {
		slog.Warn("agent report: dropped out-of-network hosts",
			"agent_id", rep.AgentID, "network_id", *networkID, "out_of_network", outOfNetwork)
	}
	for _, host := range inNetwork {
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
	// Refresh leases ONLY for the in-network alive set (resets miss_count,
	// stamps last_seen_at). Lost detection for agent networks is NO LONGER done
	// per-report (the old DetectLost call was O(whole network) each time) — the
	// background LeaseSweeper expires stale agent devices on its own slow ticker.
	h.runner.RecordAliveSnapshots(r.Context(), nid, 0, hostReportsForLease(inNetwork))

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
		"hosts", len(rep.Hosts), "added", added, "updated", updated, "skipped", skipped,
		"out_of_network", outOfNetwork)

	Success(w, reportAck{
		Accepted: added + updated, Added: added, Updated: updated, Skipped: skipped,
		OutOfNetwork: outOfNetwork,
	})
}

// resolveNetworkCIDR returns the parsed IPNet for the given network, cached.
// Returns (nil, true) when the network has no usable CIDR (degrade-open — the
// boundary check is skipped for that network). Returns (nil, false) only on a
// hard lookup failure (logged; treated as skip too, never fatal).
//
// This is the authoritative center-side enforcement of the boundary invariant
// (issue #19 Layer 2): a host whose IP falls outside its reporting agent's
// network CIDR cannot be attributed to that network, regardless of what the
// agent sends. It is the backstop for Layer 1 (which gates at command dispatch)
// — even if a command slips through (or an agent scans on its own scheduler),
// out-of-network hosts are dropped here before they reach the device bridge.
func (h *AgentReportHandler) resolveNetworkCIDR(ctx context.Context, networkID int64) *net.IPNet {
	h.cidrMu.RLock()
	if cached, ok := h.cidrCache[networkID]; ok {
		h.cidrMu.RUnlock()
		return cached // nil is a valid cached value ("no CIDR")
	}
	h.cidrMu.RUnlock()

	var ipNet *net.IPNet
	netRow, err := h.queries.GetNetwork(ctx, networkID)
	if err != nil {
		slog.Warn("agent report: cannot load network for boundary check; skipping",
			"network_id", networkID, "error", err)
		// Don't cache the failure — a transient DB error shouldn't permanently
		// disable the check. nil-but-not-cached: next report retries.
		return nil
	}
	cidr := ""
	if netRow.Cidr != nil {
		cidr = *netRow.Cidr
	}
	parsed, perr := cidrutil.ParseNetwork(cidr)
	switch {
	case errors.Is(perr, cidrutil.ErrEmptyCIDR):
		// No CIDR configured — cache nil so we don't re-query every 30s. The
		// cidr-enforcement prerequisite (issue #19 前置工作) is what fills this.
		slog.Warn("agent report: network has no cidr; boundary check disabled",
			"network_id", networkID, "network_name", netRow.Name)
	case perr != nil:
		slog.Warn("agent report: network has invalid cidr; boundary check disabled",
			"network_id", networkID, "cidr", cidr, "error", perr)
	default:
		ipNet = parsed
	}

	h.cidrMu.Lock()
	h.cidrCache[networkID] = ipNet
	h.cidrMu.Unlock()
	return ipNet
}

// invalidateNetworkCIDR clears the cached CIDR for a network (e.g. after an
// admin edits the network's cidr). Not wired yet — reserved for the network
// update handler to call when cidr-enforcement lands.
func (h *AgentReportHandler) invalidateNetworkCIDR(networkID int64) {
	h.cidrMu.Lock()
	delete(h.cidrCache, networkID)
	h.cidrMu.Unlock()
}

// maybeBackfillNetworkCIDR fills networks.cidr for networkID when the row lacks
// one, using the agent-reported cidr as the source of truth (issue #19 前置工作).
// It validates the cidr before writing (a bogus value would silently break the
// boundary checks) and is idempotent: a non-empty existing cidr wins (the admin
// or a prior report set it; don't overwrite). The cidr cache is invalidated so
// the next report re-resolves with the fresh value.
func (h *AgentReportHandler) maybeBackfillNetworkCIDR(ctx context.Context, networkID int64, reported string) {
	// Validate first — a malformed cidr in config would otherwise poison the row.
	if _, err := cidrutil.ParseNetwork(reported); err != nil {
		slog.Warn("agent report: agent-reported cidr is invalid; not backfilling",
			"network_id", networkID, "cidr", reported, "error", err)
		return
	}
	netRow, err := h.queries.GetNetwork(ctx, networkID)
	if err != nil {
		return // transient DB error; next report retries
	}
	if netRow.Cidr != nil && *netRow.Cidr != "" {
		// Already populated. If it differs, log — operator may want to know the
		// agent disagrees with the configured network geometry, but we don't
		// auto-clobber (the admin-set value is authoritative).
		if *netRow.Cidr != reported {
			slog.Warn("agent report: agent-reported cidr differs from configured; keeping configured",
				"network_id", networkID, "configured", *netRow.Cidr, "reported", reported)
		}
		return
	}
	// Raw UPDATE: networks' update path is hand-written (sqlc truncates multi-
	// bind UPDATEs — see db/queries/networks.sql UpdateNetworkRaw note). We only
	// touch cidr + updated_at, leaving the other columns untouched. The
	// `cidr IS NULL OR cidr = ''` guard makes this safe against a concurrent
	// report that already filled it.
	if _, err := h.dbConn.ExecContext(ctx,
		`UPDATE networks SET cidr = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND (cidr IS NULL OR cidr = '')`,
		reported, networkID); err != nil {
		slog.Warn("agent report: backfill networks.cidr failed", "network_id", networkID, "error", err)
		return
	}
	h.invalidateNetworkCIDR(networkID)
	slog.Info("agent report: backfilled networks.cidr from agent config",
		"network_id", networkID, "network_name", netRow.Name, "cidr", reported)
}

// filterInNetwork returns the subset of hosts that are (a) alive with a non-empty
// IP and (b) inside the network's CIDR. The second return is the count of hosts
// dropped solely by the CIDR check (dead/empty-IP hosts are neither in the
// result nor counted as out-of-network — the caller accounts for them as plain
// skips). A network with no usable CIDR degrades open: every alive host passes.
//
// This is the single place the boundary check is applied, used by both the
// device-bridge path and the stable-hash fast path so they can't drift.
func (h *AgentReportHandler) filterInNetwork(ctx context.Context, networkID int64, hosts []domain.ReportedHost) ([]domain.ReportedHost, int) {
	boundary := h.resolveNetworkCIDR(ctx, networkID)
	out := make([]domain.ReportedHost, 0, len(hosts))
	outOfNetwork := 0
	for _, host := range hosts {
		if !host.Alive || host.IP == "" {
			continue
		}
		if boundary != nil && !cidrutil.ContainsIP(boundary, host.IP) {
			outOfNetwork++
			continue
		}
		out = append(out, host)
	}
	return out, outOfNetwork
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
	Accepted     int  `json:"accepted"` // added + updated (hosts the center acted on)
	Added        int  `json:"added"`
	Updated      int  `json:"updated"`
	Skipped      int  `json:"skipped"`        // dead hosts, missing IP, or apply errors
	OutOfNetwork int  `json:"out_of_network"` // hosts dropped by the CIDR boundary check (issue #19)
	Stable       bool `json:"stable"`         // true = state hash matched, device bridge skipped
}
