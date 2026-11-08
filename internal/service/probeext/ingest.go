// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"fmt"
	"strings"

	"mibee-steward/internal/domain"
)

// AgentEgressRound is one egress round in an agent's /agents/egress-report
// batch (#718). The agent reports raw echo outcomes; origin-ASN enrichment
// stays on the center (one Cymru cache, consistent data regardless of how
// many vantages report the same pool).
type AgentEgressRound struct {
	RoundAt string                    `json:"round_at"`
	Local   AgentEgressLocal          `json:"local"`
	Results []AgentEgressSourceResult `json:"results"`
}

// AgentEgressLocal is the local-egress layer of one round: the default-route
// interface and gateway. MAC is reported for forward-compat; the center's
// local row keeps the documented convention (source="local", ip=gateway,
// err=iface) and does not persist it.
type AgentEgressLocal struct {
	Iface      string `json:"iface"`
	GatewayIP  string `json:"gateway_ip"`
	GatewayMAC string `json:"gateway_mac"`
}

// AgentEgressSourceResult is one echo source's outcome.
type AgentEgressSourceResult struct {
	Source string  `json:"source"`
	Kind   string  `json:"kind"`
	OK     bool    `json:"ok"`
	IP     string  `json:"ip"`
	MS     float64 `json:"ms"`
	Err    string  `json:"err"`
}

// AgentPathSample is one trace row in an agent's /agents/path-report batch
// (#719). TargetID + TracedAt are the agent's own; the center re-derives the
// target name from the live row so renames propagate.
type AgentPathSample struct {
	TargetID    int64     `json:"target_id"`
	TargetName  string    `json:"target_name"`
	ResolvedIP  string    `json:"resolved_ip"`
	Method      string    `json:"method"`
	EndState    string    `json:"end_state"`
	ReachedTTL  int       `json:"reached_ttl"`
	ReplyTTL    int       `json:"reply_ttl"`
	VisibleHops int       `json:"visible_hops"`
	Hops        []PathHop `json:"hops"`
	Trigger     string    `json:"trigger"`
	Err         string    `json:"err"`
	TracedAt    string    `json:"traced_at"`
}

// IngestAgentEgress persists an agent's egress rounds (#718), stamping the
// reporting agent's identity on every row (the payload's own vantage claim is
// never trusted — an agent can only write its own track). Distinct public IPs
// are ASN-enriched through the center's cache, exactly like center-collected
// rounds.
func (s *Service) IngestAgentEgress(ctx context.Context, agentID string, rounds []AgentEgressRound) (int, error) {
	vantage := domain.ProbeVantageAgentPrefix + agentID
	accepted := 0
	for _, r := range rounds {
		rows := make([]EgressRow, 0, len(r.Results)+1)
		rows = append(rows, EgressRow{
			Vantage: vantage, RoundAt: r.RoundAt,
			Source: "local", Kind: "local",
			OK: r.Local.GatewayIP != "", IP: r.Local.GatewayIP, Err: r.Local.Iface,
		})
		distinct := map[string]bool{}
		for _, o := range r.Results {
			row := EgressRow{
				Vantage: vantage, RoundAt: r.RoundAt,
				Source: o.Source, Kind: o.Kind, OK: o.OK, IP: o.IP, MS: o.MS, Err: o.Err,
			}
			if o.OK && isPublicIP(o.IP) && !distinct[o.IP] {
				distinct[o.IP] = true
				row.ASN, row.ASName = s.egress.lookupASN(ctx, o.IP)
			}
			rows = append(rows, row)
		}
		if err := s.store.InsertEgressRound(ctx, rows); err != nil {
			return accepted, fmt.Errorf("insert agent egress round: %w", err)
		}
		accepted++
	}
	if accepted > 0 {
		s.logger.Info("agent egress rounds ingested",
			"agent_id", agentID, "rounds", accepted)
	}
	return accepted, nil
}

// IngestAgentPaths persists an agent's path samples (#719). Rows for unknown
// or deleted targets are skipped (plan raced a deletion — normal operation);
// visible hops are recounted center-side so the stored summary matches the
// hops payload regardless of agent version.
func (s *Service) IngestAgentPaths(ctx context.Context, agentID string, paths []AgentPathSample) (int, error) {
	vantage := domain.ProbeVantageAgentPrefix + agentID
	accepted := 0
	for _, p := range paths {
		t, err := s.queries.GetProbeTarget(ctx, p.TargetID)
		if err != nil {
			continue // target deleted/disabled mid-flight
		}
		sample := PathSample{
			TargetID:   p.TargetID,
			TargetName: t.Name,
			Vantage:    vantage,
			ResolvedIP: p.ResolvedIP,
			Method:     p.Method,
			EndState:   p.EndState,
			ReachedTTL: p.ReachedTTL,
			ReplyTTL:   p.ReplyTTL,
			Hops:       p.Hops,
			Trigger:    triggerOr(p.Trigger),
			Err:        p.Err,
			TracedAt:   p.TracedAt,
		}
		for _, h := range p.Hops {
			if h.IP != "" {
				sample.VisibleHops++
			}
		}
		if _, err := s.store.InsertPathSample(ctx, sample); err != nil {
			return accepted, fmt.Errorf("insert agent path sample: %w", err)
		}
		accepted++
	}
	if accepted > 0 {
		s.logger.Debug("agent paths ingested",
			"agent_id", agentID, "paths", accepted)
	}
	return accepted, nil
}

// triggerOr defaults an absent trigger label (older agents, wire tolerance).
func triggerOr(trigger string) string {
	if strings.TrimSpace(trigger) == "" {
		return "baseline"
	}
	return trigger
}
