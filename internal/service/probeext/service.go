// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/probetarget"
)

// Service owns the egress rounds and path traces for the CENTER vantage
// (#718/#719 first landing). Agent vantages join when the agent-side egress
// and trace reporting lands; until then their cards render as "no data".
//
// Recording only, per the #716 ruling: nothing here writes change_log or
// fires notifications - the UI shows current state, and change-driven
// alerts come with #720's degradation detector.
type Service struct {
	store   *Store
	queries *db.Queries
	egress  *egressCollector
	tracer  *Tracer
	cfg     config.ProbeConfig
	logger  *slog.Logger

	mu         sync.Mutex
	nextEgress time.Time
	nextTrace  map[int64]time.Time // target id -> due
}

// NewService builds the service. queries reads probe_targets for the trace
// scheduler (category + target host/port derivation).
func NewService(cfg config.ProbeConfig, store *Store, queries *db.Queries, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		store:     store,
		queries:   queries,
		egress:    newEgressCollector(cfg.Egress, logger),
		tracer:    NewTracer(cfg.Trace.MaxTTL, cfg.Trace.PerHopMs, 1),
		cfg:       cfg,
		logger:    logger,
		nextTrace: make(map[int64]time.Time),
	}
}

// Start launches the scheduler loop (one goroutine, 30s tick): egress rounds
// every probe.egress.interval_seconds, path traces per due target limited
// to the configured categories and concurrency.
func (s *Service) Start(ctx context.Context) {
	s.startLoop(ctx, 30*time.Second)
}

// startLoop is Start with an injectable tick interval (tests).
func (s *Service) startLoop(ctx context.Context, every time.Duration) {
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.tick(ctx)
			}
		}
	}()
}

func (s *Service) tick(ctx context.Context) {
	now := time.Now()
	s.mu.Lock()
	egressDue := s.nextEgress.IsZero() || !now.Before(s.nextEgress)
	if egressDue {
		s.nextEgress = now.Add(time.Duration(s.cfg.Egress.IntervalSeconds) * time.Second)
	}
	s.mu.Unlock()
	if s.cfg.Egress.Enabled && egressDue {
		if err := s.egress.round(ctx, s.store); err != nil {
			s.logger.Warn("egress round failed", "error", err)
		}
	}
	if len(s.cfg.Trace.Categories) == 0 {
		return
	}
	s.traceDueTargets(ctx, now)
}

// traceCategorySet is the configured category allow-list.
func (s *Service) traceCategoryOK(cat string) bool {
	for _, c := range s.cfg.Trace.Categories {
		if c == cat {
			return true
		}
	}
	return false
}

// traceDueTargets walks enabled targets, traces the due ones (interval per
// target, staggered by target id on first sight), concurrency-bounded.
func (s *Service) traceDueTargets(ctx context.Context, now time.Time) {
	targets, err := s.queries.ListEnabledProbeTargets(ctx)
	if err != nil {
		s.logger.Warn("path scheduler: list targets failed", "error", err)
		return
	}
	interval := time.Duration(s.cfg.Trace.IntervalMinutes) * time.Minute
	var jobs []db.ProbeTarget
	s.mu.Lock()
	for _, t := range targets {
		if !s.traceCategoryOK(probetarget.TargetCategory(t)) {
			continue
		}
		due, ok := s.nextTrace[t.ID]
		if !ok {
			// First sight after start: stagger within the interval so a
			// restart does not fire every trace at once.
			s.nextTrace[t.ID] = now.Add(time.Duration(t.ID%int64(len(jobs)+1)) * interval / 16)
			continue
		}
		if now.Before(due) {
			continue
		}
		s.nextTrace[t.ID] = now.Add(interval)
		jobs = append(jobs, t)
	}
	s.mu.Unlock()
	if len(jobs) == 0 {
		return
	}
	sem := make(chan struct{}, s.cfg.Trace.Concurrency)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(t db.ProbeTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if _, err := s.traceTarget(ctx, t, "baseline"); err != nil {
				s.logger.Warn("path trace failed", "target", t.Name, "error", err)
			}
		}(j)
	}
	wg.Wait()
}

// traceTarget derives host/port from the target string, runs one trace and
// stores the sample.
func (s *Service) traceTarget(ctx context.Context, t db.ProbeTarget, trigger string) (PathSample, error) {
	host, port := hostPortForTrace(t)
	sample := PathSample{
		TargetID: t.ID, TargetName: t.Name, Vantage: vantageCenter,
		Trigger: trigger, TracedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if host == "" {
		sample.EndState = "error"
		sample.Err = "cannot derive host from target"
		id, _ := s.store.InsertPathSample(ctx, sample)
		sample.ID = id
		return sample, nil
	}
	res := s.tracer.TraceHost(ctx, host, port, "auto")
	sample.Method = res.Method
	sample.ResolvedIP = res.DstIP
	sample.EndState = res.EndState
	sample.ReachedTTL = res.ReachedTTL
	sample.ReplyTTL = res.ReplyTTL
	sample.Err = res.Err
	sample.Hops = res.Hops
	for _, h := range res.Hops {
		if h.IP != "" {
			sample.VisibleHops++
		}
	}
	id, err := s.store.InsertPathSample(ctx, sample)
	if err != nil {
		return sample, fmt.Errorf("store path sample: %w", err)
	}
	sample.ID = id
	return sample, nil
}

// hostPortForTrace maps a probe target string to (host, port) for tracing:
// http/https URLs give host + scheme port; tcp targets are host:port; icmp
// and dns targets give host + 0 (ICMP method).
func hostPortForTrace(t db.ProbeTarget) (string, int) {
	switch t.Module {
	case "http":
		if u, err := url.Parse(t.Target); err == nil && u.Host != "" {
			host := u.Hostname()
			port := 80
			if u.Scheme == "https" {
				port = 443
			}
			if p := u.Port(); p != "" {
				if n, err := strconv.Atoi(p); err == nil {
					port = n
				}
			}
			return host, port
		}
		return strings.TrimPrefix(strings.TrimPrefix(t.Target, "https://"), "http://"), 80
	case "tls", "tcp":
		if host, portStr, ok := strings.Cut(t.Target, ":"); ok {
			port, _ := strconv.Atoi(portStr)
			return host, port
		}
		return t.Target, 0
	default: // icmp, dns
		return t.Target, 0
	}
}

// TraceNow is the manual trigger (probe:manage): one synchronous trace.
func (s *Service) TraceNow(ctx context.Context, targetID int64) (PathSample, error) {
	t, err := s.queries.GetProbeTarget(ctx, targetID)
	if err != nil {
		return PathSample{}, fmt.Errorf("target %d: %w", targetID, err)
	}
	return s.traceTarget(ctx, t, "manual")
}

// EgressSnapshot is the GET /probe-egress payload.
func (s *Service) EgressSnapshot(ctx context.Context) ([]EgressVantageView, error) {
	views, err := s.store.LatestEgress(ctx, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	names := s.agentNetworkNames(ctx)
	for i := range views {
		views[i].NetworkName = vantageDisplayName(views[i].Vantage, views[i].NetworkName, names)
	}
	return views, nil
}

// agentNetworkNames maps agent id → its network's name (agent vantages are
// "agent:{id}" tokens; the UI prefers the human name).
func (s *Service) agentNetworkNames(ctx context.Context) map[string]string {
	nets, err := s.queries.ListNetworks(ctx)
	if err != nil {
		return nil
	}
	names := make(map[string]string, len(nets))
	for _, n := range nets {
		if n.AgentID != nil && *n.AgentID != "" && n.Name != "" {
			names[*n.AgentID] = n.Name
		}
	}
	return names
}

// vantageDisplayName resolves an agent vantage token to its network name,
// leaving existing names and the center track untouched.
func vantageDisplayName(vantage, current string, names map[string]string) string {
	if current != "" {
		return current
	}
	if id, ok := strings.CutPrefix(vantage, domain.ProbeVantageAgentPrefix); ok {
		return names[id]
	}
	return ""
}

// PathsSnapshot is the GET /probe-paths payload (latest per target×vantage),
// annotated with the target's module/category for the UI.
func (s *Service) PathsSnapshot(ctx context.Context) ([]map[string]any, error) {
	paths, err := s.store.LatestPaths(ctx, "")
	if err != nil {
		return nil, err
	}
	targets, err := s.queries.ListProbeTargets(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]db.ProbeTarget, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
	}
	names := s.agentNetworkNames(ctx)
	out := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		row := map[string]any{
			"id": p.ID, "target_id": p.TargetID, "target_name": p.TargetName,
			"vantage": p.Vantage, "resolved_ip": p.ResolvedIP, "method": p.Method,
			"end_state": p.EndState, "reached_ttl": p.ReachedTTL, "reply_ttl": p.ReplyTTL,
			"visible_hops": p.VisibleHops, "hops": p.Hops, "trigger": p.Trigger,
			"err": p.Err, "traced_at": p.TracedAt,
		}
		if name := vantageDisplayName(p.Vantage, "", names); name != "" {
			row["network_name"] = name
		}
		if t, ok := byID[p.TargetID]; ok {
			row["module"] = t.Module
			row["target"] = t.Target
			row["category"] = probetarget.TargetCategory(t)
		}
		out = append(out, row)
	}
	return out, nil
}

// ListTargetPaths is the per-target history (GET /probe-targets/{id}/paths).
func (s *Service) ListTargetPaths(ctx context.Context, targetID int64, limit int) ([]PathSample, error) {
	return s.store.ListPathsByTarget(ctx, targetID, limit)
}

// ListTargetPhases is the per-target per-stage timing history (#717,
// GET /probe-targets/{id}/phases).
func (s *Service) ListTargetPhases(ctx context.Context, targetID int64, limit int) ([]PhaseRow, error) {
	return s.store.ListPhasesFor(ctx, targetID, limit)
}
