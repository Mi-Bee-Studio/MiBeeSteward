// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// CommandEnqueuer is the slice of AgentCommandService the dispatcher needs.
// An interface keeps probetarget decoupled from the agent-command service
// (and lets tests stub enqueueing without the command tables).
type CommandEnqueuer interface {
	Enqueue(ctx context.Context, agentID, command string, payload map[string]interface{}) (db.AgentCommand, error)
}

// Spec is ONE target's execution definition as shipped to an agent
// inside the "probe" command payload. The agent runs it on its own schedule
// and reports results tagged with the vantage it was given. Options rides
// along as raw JSON (already validated at CRUD time) so the agent codec sees
// exactly what the center validated - the Rust side decodes the same shape.
// Category is derived center-side (TargetCategory) so the agent can apply
// the trace plan's category allow-list without replicating the derivation.
type Spec struct {
	ID              int64           `json:"id"`
	Name            string          `json:"name"`
	Module          string          `json:"module"`
	Target          string          `json:"target"`
	IntervalSeconds int             `json:"interval_seconds"`
	TimeoutSeconds  int             `json:"timeout_seconds"`
	Vantage         string          `json:"vantage"`
	Category        string          `json:"category,omitempty"`
	Options         json.RawMessage `json:"options,omitempty"`
}

// TracePlan is the agent-side path-trace schedule riding the "probe" plan
// (#719): which target categories to trace, how often, with what per-hop
// budget. Shipped only to agents that declared the `trace` capability; nil
// trace = tracing disabled on that agent.
type TracePlan struct {
	Categories      []string `json:"categories"`
	IntervalMinutes int      `json:"interval_minutes"`
	MaxTTL          int      `json:"max_ttl"`
	PerHopMs        int      `json:"per_hop_ms"`
}

// planRefreshInterval bounds how long a restarted agent stays planless. The
// fingerprint dedup assumes the agent still holds the last plan, but an agent
// restart wipes ITS copy while this side still records the fingerprint as
// sent, so unchanged plans are re-shipped periodically (re-applying a plan is
// a no-op on the agent).
const planRefreshInterval = 5 * time.Minute

// legacySupportedModules is the assumed capability set of an agent that never
// reported capabilities (#604): exactly what the historical agent binary could
// execute. tcp is absent on purpose - pre-capability agents fail tcp probes
// with "unknown module" (a live bug), so the dispatcher shields them from tcp
// plans until they upgrade and declare support.
var legacySupportedModules = map[string]bool{"icmp": true, "http": true, "tls": true}

// AgentDispatcher ships vantage probe plans to agents over the command
// channel (#277 step 2). It is NOT a scheduler: agents run their own
// intervals locally. The dispatcher only (re)sends a plan when the plan's
// content changed, a sha256 over the agent's sorted specs, so the steady
// state is near-zero command traffic, and a config edit propagates within one
// dispatch tick.
type AgentDispatcher struct {
	queries *db.Queries
	enqueue CommandEnqueuer
	logger  *slog.Logger
	cfg     config.ProbeConfig

	// lastFingerprint per agentID of the last plan successfully enqueued.
	lastFingerprint map[string]string
	// lastSentAt per agentID of that enqueue, for the periodic refresh.
	lastSentAt map[string]time.Time
	// lastHeldBack per agentID of the module-unsupported targets held back on
	// the last tick, so the upgrade hint logs once per change, not every tick.
	lastHeldBack map[string]int
	// Egress plan lane (#718): same fingerprint+refresh mechanics, own maps
	// so plan changes never cross-talk between the two command types.
	lastEgressFp map[string]string
	lastEgressAt map[string]time.Time
}

func NewAgentDispatcher(queries *db.Queries, enqueue CommandEnqueuer, logger *slog.Logger, cfg config.ProbeConfig) *AgentDispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &AgentDispatcher{
		queries:         queries,
		enqueue:         enqueue,
		logger:          logger,
		cfg:             cfg,
		lastFingerprint: make(map[string]string),
		lastSentAt:      make(map[string]time.Time),
		lastHeldBack:    make(map[string]int),
		lastEgressFp:    make(map[string]string),
		lastEgressAt:    make(map[string]time.Time),
	}
}

// DispatchTick lists enabled targets, groups the agent-vantage ones
// ('agent:{id}' exclusively, 'all' additionally to the center track) per
// agent, and enqueues a "probe" plan for any agent whose plan changed.
// Targets whose module the agent cannot execute are held back per its
// declared capabilities (#604). Called on the same 10s cadence as the engine
// tick by the center wiring.
func (d *AgentDispatcher) DispatchTick(ctx context.Context) {
	targets, err := d.queries.ListEnabledProbeTargets(ctx)
	if err != nil {
		d.logger.Error("probe dispatch: list targets failed", "error", err)
		return
	}
	agents := d.knownAgents(ctx)
	caps := d.agentCapabilities(ctx)

	perAgent := make(map[string][]db.ProbeTarget)
	heldBack := make(map[string]int)
	ship := func(agentID string, t db.ProbeTarget) {
		if !agentSupports(caps, agentID, t.Module) {
			heldBack[agentID]++
			return
		}
		perAgent[agentID] = append(perAgent[agentID], t)
	}
	for _, t := range targets {
		switch {
		case t.Vantage == domain.ProbeVantageAll:
			// 'all' runs on every known agent in addition to the center.
			for _, agentID := range agents {
				ship(agentID, t)
			}
		case strings.HasPrefix(t.Vantage, domain.ProbeVantageAgentPrefix):
			agentID := strings.TrimPrefix(t.Vantage, domain.ProbeVantageAgentPrefix)
			if agentID == "" {
				continue
			}
			ship(agentID, t)
		}
	}

	for agentID, list := range perAgent {
		if err := d.sendPlan(ctx, agentID, list, caps); err != nil {
			d.logger.Error("probe dispatch: enqueue plan failed", "agent_id", agentID, "error", err)
		}
	}
	// Egress echo plans (#718): capability-gated lane, independent cadence.
	d.dispatchEgress(ctx, agents, caps)
	// An agent whose every target was deleted gets an EMPTY plan once, so its
	// local prober stops cleanly instead of probing ghosts forever.
	for _, agentID := range agents {
		if _, ok := perAgent[agentID]; ok {
			continue
		}
		if d.lastFingerprint[agentID] == "" {
			continue // never had a plan: nothing to clear
		}
		if err := d.sendPlan(ctx, agentID, nil, caps); err != nil {
			d.logger.Warn("probe dispatch: clear plan failed", "agent_id", agentID, "error", err)
		}
	}
	// Capability hold-back bookkeeping: log a change once (upgrade hint), not
	// on every 10s tick; a clean agent drops its stale hint.
	for _, agentID := range agents {
		n := heldBack[agentID]
		if d.lastHeldBack[agentID] != n {
			if n > 0 {
				d.logger.Warn("probe dispatch: agent lacks module support, targets held back",
					"agent_id", agentID, "held_back", n,
					"hint", "upgrade to mibee-agent 0.2.0+ for tcp/dns execution")
			}
			d.lastHeldBack[agentID] = n
		}
	}
}

// knownAgents returns the agent IDs that currently have a network bound
// (networks.agent_id), the same population the scan dispatcher routes to.
func (d *AgentDispatcher) knownAgents(ctx context.Context) []string {
	nets, err := d.queries.ListNetworks(ctx)
	if err != nil {
		d.logger.Warn("probe dispatch: list networks failed", "error", err)
		return nil
	}
	var ids []string
	for _, n := range nets {
		if n.AgentID != nil && strings.TrimSpace(*n.AgentID) != "" {
			ids = append(ids, strings.TrimSpace(*n.AgentID))
		}
	}
	return ids
}

// agentCapabilities reads the per-agent declared probe module set from
// agent_status (#604). Agents that never reported capabilities are absent
// from the map and fall back to legacySupportedModules at the call site.
func (d *AgentDispatcher) agentCapabilities(ctx context.Context) map[string]map[string]bool {
	rows, err := d.queries.ListAgentStatus(ctx)
	if err != nil {
		d.logger.Warn("probe dispatch: list agent status failed", "error", err)
		return nil
	}
	caps := make(map[string]map[string]bool, len(rows))
	for _, r := range rows {
		if strings.TrimSpace(r.SupportedModules) == "" {
			continue
		}
		set := make(map[string]bool)
		for _, m := range strings.Split(r.SupportedModules, ",") {
			if m = strings.TrimSpace(m); m != "" {
				set[m] = true
			}
		}
		if len(set) > 0 {
			caps[r.AgentID] = set
		}
	}
	return caps
}

// agentSupports decides whether one agent may execute one module: its
// declared set when it reported capabilities, the legacy set otherwise.
func agentSupports(caps map[string]map[string]bool, agentID, module string) bool {
	if set, ok := caps[agentID]; ok {
		return set[module]
	}
	return legacySupportedModules[module]
}

// sendPlan enqueues a "probe" command for one agent when (and only when) the
// plan content changed. The payload carries the plan's fingerprint so the
// agent can log a repeated plan. Agents that declared the `trace` capability
// additionally receive the center's trace schedule (#719), and the
// fingerprint covers it: a trace-config change re-pushes the plan.
func (d *AgentDispatcher) sendPlan(ctx context.Context, agentID string, list []db.ProbeTarget, caps map[string]map[string]bool) error {
	specs := make([]Spec, 0, len(list))
	for _, t := range list {
		var opts json.RawMessage
		if strings.TrimSpace(t.Options) != "" {
			opts = json.RawMessage(t.Options)
		}
		specs = append(specs, Spec{
			ID: t.ID, Name: t.Name, Module: t.Module, Target: t.Target,
			IntervalSeconds: int(t.IntervalSeconds), TimeoutSeconds: int(t.TimeoutSeconds),
			Vantage:  agentVantageFor(t.Vantage, agentID),
			Category: TargetCategory(t),
			Options:  opts,
		})
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })

	var trace *TracePlan
	if agentSupports(caps, agentID, "trace") && len(d.cfg.Trace.Categories) > 0 {
		trace = &TracePlan{
			Categories:      d.cfg.Trace.Categories,
			IntervalMinutes: d.cfg.Trace.IntervalMinutes,
			MaxTTL:          d.cfg.Trace.MaxTTL,
			PerHopMs:        d.cfg.Trace.PerHopMs,
		}
	}

	fp := PlanFingerprint(specs, trace)
	unchanged := fp == d.lastFingerprint[agentID]
	// Empty plans keep their send-once semantics: an unchanged empty plan
	// carries no state to refresh, re-sending it would only spam the log.
	if unchanged && (len(specs) == 0 || time.Since(d.lastSentAt[agentID]) < planRefreshInterval) {
		return nil // the agent already has this plan
	}
	payload := map[string]interface{}{
		"targets":     specs,
		"fingerprint": fp,
	}
	if trace != nil {
		payload["trace"] = trace
	}
	if _, err := d.enqueue.Enqueue(ctx, agentID, "probe", payload); err != nil {
		return fmt.Errorf("enqueue probe plan (%d targets): %w", len(specs), err)
	}
	d.lastFingerprint[agentID] = fp
	d.lastSentAt[agentID] = time.Now()
	if len(specs) == 0 {
		d.logger.Info("probe dispatch: plan cleared", "agent_id", agentID)
	} else {
		d.logger.Info("probe dispatch: plan shipped", "agent_id", agentID, "targets", len(specs))
	}
	return nil
}

// dispatchEgress ships the egress echo plan (#718) — the configured echo
// sources + cadence — to every agent that declared the `egress` capability.
// Same fingerprint-dedup + periodic-refresh mechanics as probe plans; an
// egress-disabled center sends one empty plan to previously-planned agents so
// their local rounds stop cleanly.
func (d *AgentDispatcher) dispatchEgress(ctx context.Context, agents []string, caps map[string]map[string]bool) {
	sources := d.cfg.Egress.Sources
	if d.cfg.Egress.Enabled {
		sources = append([]config.ProbeEgressSource(nil), sources...)
	} else {
		sources = nil
	}
	interval := d.cfg.Egress.IntervalSeconds
	fp := egressFingerprint(sources, interval)

	for _, agentID := range agents {
		if !agentSupports(caps, agentID, "egress") {
			continue
		}
		if len(sources) == 0 && d.lastEgressFp[agentID] == "" {
			continue // never had an egress plan: nothing to clear
		}
		unchanged := fp == d.lastEgressFp[agentID]
		if unchanged && (len(sources) == 0 || time.Since(d.lastEgressAt[agentID]) < planRefreshInterval) {
			continue
		}
		payload := map[string]interface{}{
			"sources":          sources,
			"interval_seconds": interval,
			"fingerprint":      fp,
		}
		if _, err := d.enqueue.Enqueue(ctx, agentID, "egress", payload); err != nil {
			d.logger.Error("egress dispatch: enqueue plan failed", "agent_id", agentID, "error", err)
			continue
		}
		d.lastEgressFp[agentID] = fp
		d.lastEgressAt[agentID] = time.Now()
		if len(sources) == 0 {
			d.logger.Info("egress dispatch: plan cleared", "agent_id", agentID)
		} else {
			d.logger.Info("egress dispatch: plan shipped", "agent_id", agentID, "sources", len(sources))
		}
	}
}

// agentVantageFor canonicalizes the vantage the AGENT should stamp on its
// results: an 'all' plan becomes this agent's track ('agent:{id}'); an
// agent-specific plan stays as-is.
func agentVantageFor(planVantage, agentID string) string {
	if planVantage == domain.ProbeVantageAll {
		return domain.ProbeVantageAgentPrefix + agentID
	}
	return planVantage
}

// PlanFingerprint hashes a sorted spec list plus the trace block so the
// dispatcher can skip enqueueing unchanged plans (steady state = zero command
// traffic). A trace-config change alone changes the fingerprint, so it
// re-pushes without waiting for a target edit.
func PlanFingerprint(specs []Spec, trace *TracePlan) string {
	b, _ := json.Marshal(struct {
		Targets []Spec     `json:"targets"`
		Trace   *TracePlan `json:"trace,omitempty"`
	}{specs, trace})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// egressFingerprint hashes the echo-source set + cadence (#718 plan lane).
func egressFingerprint(sources []config.ProbeEgressSource, intervalSeconds int) string {
	b, _ := json.Marshal(struct {
		Sources []config.ProbeEgressSource `json:"sources"`
		Every   int                        `json:"interval_seconds"`
	}{sources, intervalSeconds})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AgentResultReport is ONE result row in an agent's probe-report batch.
// TargetID + Vantage identify the track; CheckedAt is the agent's clock at
// probe time (RFC3339), which the ingest path treats as authoritative for
// ordering (agents may buffer during center downtime).
type AgentResultReport struct {
	TargetID     int64   `json:"target_id"`
	Vantage      string  `json:"vantage"`
	Status       string  `json:"status"`
	LatencyMs    float64 `json:"latency_ms"`
	StatusCode   int     `json:"status_code"`
	ErrorMessage string  `json:"error_message"`
	TLSVersion   string  `json:"tls_version"`
	CertNotAfter string  `json:"cert_not_after"`
	CertTrusted  *bool   `json:"cert_trusted"`
	CheckedAt    string  `json:"checked_at"`
}

// IngestAgentResults persists a batch of agent-side probe results (#277).
// The reporting agent's identity (from its token) overrides whatever vantage
// the payload claims, an agent can only ever write its own track.
// Rows for unknown/deleted targets are skipped, not failed: a plan removal
// racing an in-flight report is normal operation.
func (s *Service) IngestAgentResults(ctx context.Context, agentID string, results []AgentResultReport) (int, error) {
	own := domain.ProbeVantageAgentPrefix + agentID
	accepted := 0
	for _, r := range results {
		t, err := s.queries.GetProbeTarget(ctx, r.TargetID)
		if err != nil {
			continue // plan raced: target deleted/disabled mid-flight
		}
		// Gauge first (failure logged), then persistence.
		s.engine.metrics.record(t.Name, t.Module, own, r.Status, r.LatencyMs/1000.0, certExpiryUnix(r.CertNotAfter))
		if err := s.queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
			TargetID:     r.TargetID,
			Status:       r.Status,
			LatencyMs:    r.LatencyMs,
			StatusCode:   int64(r.StatusCode),
			ErrorMessage: r.ErrorMessage,
			TlsVersion:   r.TLSVersion,
			CertNotAfter: r.CertNotAfter,
			CertTrusted:  certTrustedDB(r.CertTrusted),
			CheckedAt:    r.CheckedAt,
			Vantage:      own,
		}); err != nil {
			return accepted, err
		}
		accepted++

		// Liveness transitions on the agent's own track, same state machine as
		// the center's: a site fine from the center but dead from this agent's
		// network is a vantage-local outage worth notifying (after_data carries
		// the vantage; the notification identity stays target-level so a
		// everywhere-outage still dispatches once per rule cooldown).
		// System quality-matrix targets are EXEMPT (#720) — the episode
		// detector owns their alerting (impact-confirmed, attributed).
		if s.engine != nil && s.engine.recorder != nil && t.Source != domain.ProbeSourceSystem {
			if ct := s.engine.transitions.observe(r.TargetID, own, "", r.Status); ct != "" {
				s.engine.recorder.Record(ctx, changedetect.ChangeEvent{
					ChangeType: ct,
					EntityType: changedetect.EntityTypeProbeTarget,
					DeviceID:   r.TargetID,
					After: map[string]any{
						"target_name": t.Name,
						"module":      t.Module,
						"target":      t.Target,
						"vantage":     own,
						"status":      r.Status,
						"error":       r.ErrorMessage,
					},
				})
			}
		}
	}
	return accepted, nil
}
