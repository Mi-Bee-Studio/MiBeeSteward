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
// and reports results tagged with the vantage it was given.
type Spec struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Module          string `json:"module"`
	Target          string `json:"target"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	Vantage         string `json:"vantage"`
}

// AgentDispatcher ships vantage probe plans to agents over the command
// channel (#277 step 2). It is NOT a scheduler: agents run their own
// intervals locally. The dispatcher only (re)sends a plan when the plan's
// content changed — a sha256 over the agent's sorted specs — so the steady
// state is zero command traffic, and a config edit propagates within one
// dispatch tick.
type AgentDispatcher struct {
	queries *db.Queries
	enqueue CommandEnqueuer
	logger  *slog.Logger

	// lastFingerprint per agentID of the last plan successfully enqueued.
	lastFingerprint map[string]string
}

func NewAgentDispatcher(queries *db.Queries, enqueue CommandEnqueuer, logger *slog.Logger) *AgentDispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &AgentDispatcher{
		queries:         queries,
		enqueue:         enqueue,
		logger:          logger,
		lastFingerprint: make(map[string]string),
	}
}

// DispatchTick lists enabled targets, groups the agent-vantage ones
// ('agent:{id}' exclusively, 'all' additionally to the center track) per
// agent, and enqueues a "probe" plan for any agent whose plan changed.
// Called on the same 10s cadence as the engine tick by the center wiring.
func (d *AgentDispatcher) DispatchTick(ctx context.Context) {
	targets, err := d.queries.ListEnabledProbeTargets(ctx)
	if err != nil {
		d.logger.Error("probe dispatch: list targets failed", "error", err)
		return
	}
	agents := d.knownAgents(ctx)

	perAgent := make(map[string][]db.ProbeTarget)
	for _, t := range targets {
		switch {
		case t.Vantage == domain.ProbeVantageAll:
			// 'all' runs on every known agent in addition to the center.
			for _, agentID := range agents {
				perAgent[agentID] = append(perAgent[agentID], t)
			}
		case strings.HasPrefix(t.Vantage, domain.ProbeVantageAgentPrefix):
			agentID := strings.TrimPrefix(t.Vantage, domain.ProbeVantageAgentPrefix)
			if agentID == "" {
				continue
			}
			perAgent[agentID] = append(perAgent[agentID], t)
		}
	}

	for agentID, list := range perAgent {
		if err := d.sendPlan(ctx, agentID, list); err != nil {
			d.logger.Error("probe dispatch: enqueue plan failed", "agent_id", agentID, "error", err)
		}
	}
	// An agent whose every target was deleted gets an EMPTY plan once, so its
	// local prober stops cleanly instead of probing ghosts forever.
	for _, agentID := range agents {
		if _, ok := perAgent[agentID]; ok {
			continue
		}
		if d.lastFingerprint[agentID] == "" {
			continue // never had a plan — nothing to clear
		}
		if err := d.sendPlan(ctx, agentID, nil); err != nil {
			d.logger.Warn("probe dispatch: clear plan failed", "agent_id", agentID, "error", err)
		}
	}
}

// knownAgents returns the agent IDs that currently have a network bound
// (networks.agent_id) — the same population the scan dispatcher routes to.
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

// sendPlan enqueues a "probe" command for one agent when (and only when) the
// plan content changed. The payload carries the plan's fingerprint so the
// agent can log idempotent re-application.
func (d *AgentDispatcher) sendPlan(ctx context.Context, agentID string, list []db.ProbeTarget) error {
	specs := make([]Spec, 0, len(list))
	for _, t := range list {
		specs = append(specs, Spec{
			ID: t.ID, Name: t.Name, Module: t.Module, Target: t.Target,
			IntervalSeconds: int(t.IntervalSeconds), TimeoutSeconds: int(t.TimeoutSeconds),
			Vantage: agentVantageFor(t.Vantage, agentID),
		})
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })

	fp := PlanFingerprint(specs)
	if fp == d.lastFingerprint[agentID] {
		return nil // unchanged plan: the agent already has it
	}
	payload := map[string]interface{}{
		"targets":     specs,
		"fingerprint": fp,
	}
	if _, err := d.enqueue.Enqueue(ctx, agentID, "probe", payload); err != nil {
		return fmt.Errorf("enqueue probe plan (%d targets): %w", len(specs), err)
	}
	d.lastFingerprint[agentID] = fp
	if len(specs) == 0 {
		d.logger.Info("probe dispatch: plan cleared", "agent_id", agentID)
	} else {
		d.logger.Info("probe dispatch: plan shipped", "agent_id", agentID, "targets", len(specs))
	}
	return nil
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

// PlanFingerprint hashes a sorted spec list so the dispatcher can skip
// enqueueing unchanged plans (steady state = zero command traffic).
func PlanFingerprint(specs []Spec) string {
	b, _ := json.Marshal(specs)
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
// the payload claims — an agent can only ever write its own track.
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
		// Gauge first (best-effort), then persistence.
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
	}
	return accepted, nil
}
