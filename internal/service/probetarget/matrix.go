// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"mibee-steward/internal/domain"
)

// Site-to-site matrix (#748): the N×N view over the mesh-* autogen targets
// (#747). The data plane has existed since #747 — every ordered agent pair
// plus center→agent is a burst icmp target — but reading it meant scrolling
// a flat target list. This turns those legs into rows=source, columns=
// destination with the window's RTT/loss/jitter per cell.
//
// Row/column identity comes from the leg's own metadata, NOT from parsing
// the target name: agent ids may themselves contain "-", so
// "mesh-a-b-to-c-d" is ambiguous as a string. The source is the leg's
// target.vantage (who executes the probe); the destination is resolved by
// matching target.target (the IP) against agent_status.last_source_ip, which
// is exactly how the autogen sweep built the leg in the first place.

// probeMatrixLegPrefix mirrors autogen's meshTargetPrefix. Kept as a local
// const so this file has no ordering dependency on autogen.go.
const probeMatrixLegPrefix = "mesh-"

// MatrixCell is one (source, destination) pair's window aggregate. A cell
// with Samples == 0 means the leg has not reported in the window (parked
// target, agent offline, or the sweep has not run yet) — the UI renders it
// as an em dash, never as a zero-latency success.
type MatrixCell struct {
	Source      string  `json:"source"`      // center | agent:{id}
	Destination string  `json:"destination"` // center | agent:{id}
	TargetID    int64   `json:"target_id"`
	Target      string  `json:"target"`  // the probed IP
	Enabled     bool    `json:"enabled"` // parked legs are reported, greyed
	Samples     int     `json:"samples"`
	OkRate      float64 `json:"ok_rate"`
	P50Ms       float64 `json:"p50_ms"`
	LossPct     float64 `json:"loss_pct"`
	JitterMs    float64 `json:"jitter_ms"`
	LastStatus  string  `json:"last_status,omitempty"`
}

// MatrixNode is one axis entry (a site).
type MatrixNode struct {
	ID          string `json:"id"`    // center | agent:{id}
	Label       string `json:"label"` // display name: "Center" or the network/agent name
	NetworkName string `json:"network_name,omitempty"`
}

// ProbeMatrix is the GET /api/v1/probe-matrix payload.
type ProbeMatrix struct {
	WindowMinutes int          `json:"window_minutes"`
	Sources       []MatrixNode `json:"sources"`
	Destinations  []MatrixNode `json:"destinations"`
	Cells         []MatrixCell `json:"cells"`
	// GeneratedAt lets the UI show staleness without a second clock source.
	GeneratedAt string `json:"generated_at"`
}

// BuildMatrix aggregates the mesh legs over the window and returns the N×N
// grid. Missing legs and unreported legs both simply produce no cell.
func (s *QualityService) BuildMatrix(ctx context.Context, windowMinutes int) (ProbeMatrix, error) {
	cfg := s.effective()
	if windowMinutes <= 0 {
		windowMinutes = cfg.WindowMinutes
	}
	cutoff := time.Now().UTC().Add(-time.Duration(windowMinutes) * time.Minute).Format(time.RFC3339)

	targets, err := s.queries.ListProbeTargets(ctx)
	if err != nil {
		return ProbeMatrix{}, fmt.Errorf("probe matrix: list targets: %w", err)
	}
	rows, err := s.queries.ListProbeResultsSince(ctx, cutoff)
	if err != nil {
		return ProbeMatrix{}, fmt.Errorf("probe matrix: results since: %w", err)
	}
	fleet, err := s.queries.ListAgentStatus(ctx)
	if err != nil {
		return ProbeMatrix{}, fmt.Errorf("probe matrix: list agents: %w", err)
	}
	nets, err := s.queries.ListNetworks(ctx)
	if err != nil {
		return ProbeMatrix{}, fmt.Errorf("probe matrix: list networks: %w", err)
	}

	// Site identity: agent id → node. The destination of a leg is the agent
	// whose last report came from that leg's target IP.
	nodeByAgent := make(map[string]MatrixNode, len(fleet))
	agentByIP := make(map[string]string, len(fleet))
	for _, a := range fleet {
		id := strings.TrimSpace(a.AgentID)
		if id == "" {
			continue
		}
		node := MatrixNode{ID: domain.ProbeVantageAgentPrefix + id, Label: id}
		if ip := strings.TrimSpace(a.LastSourceIp); ip != "" {
			agentByIP[ip] = id
		}
		if hn := strings.TrimSpace(a.Hostname); hn != "" {
			node.Label = hn
		}
		nodeByAgent[id] = node
	}
	for _, n := range nets {
		if n.AgentID == nil {
			continue
		}
		id := strings.TrimSpace(*n.AgentID)
		if node, ok := nodeByAgent[id]; ok {
			node.NetworkName = n.Name
			nodeByAgent[id] = node
		}
	}
	centerNode := MatrixNode{ID: domain.ProbeVantageCenter, Label: "center"}

	// Window aggregation per (target, vantage), same shape the quality
	// analyzer uses so the two views never disagree about a leg.
	type aggKey struct {
		targetID int64
		vantage  string
	}
	agg := make(map[aggKey]*trackAgg)
	for _, r := range rows {
		k := aggKey{r.TargetID, r.Vantage}
		a := agg[k]
		if a == nil {
			a = &trackAgg{latencies: make([]float64, 0, 8)}
			agg[k] = a
		}
		a.samples++
		a.last = r.Status
		if r.Status == "success" {
			a.ok++
			if r.LatencyMs > 0 {
				a.latencies = append(a.latencies, r.LatencyMs)
			}
		}
		a.lossSum += r.LossPct
		a.lossN++
		a.jitterSum += r.JitterMs
		a.jitterN++
	}

	sources := map[string]bool{domain.ProbeVantageCenter: true}
	destinations := map[string]bool{domain.ProbeVantageCenter: true}
	cells := make([]MatrixCell, 0, len(targets))
	for _, t := range targets {
		if !strings.HasPrefix(t.Name, probeMatrixLegPrefix) {
			continue
		}
		src := t.Vantage
		if src == "" {
			src = domain.ProbeVantageCenter
		}
		dstAgent, ok := agentByIP[strings.TrimSpace(t.Target)]
		if !ok {
			// The destination agent deregistered (or its address moved):
			// the leg is parked by autogen, and there is no axis entry to
			// hang it on. Skip rather than invent a phantom column.
			continue
		}
		dst := domain.ProbeVantageAgentPrefix + dstAgent
		cells = append(cells, MatrixCell{
			Source: src, Destination: dst,
			TargetID: t.ID, Target: t.Target, Enabled: t.Enabled == 1,
		})
		sources[src] = true
		destinations[dst] = true
	}

	// Fill the aggregates, then sort cells deterministically.
	byTargetVantage := make(map[aggKey]QualityTrackStats, len(agg))
	for k, a := range agg {
		byTargetVantage[aggKey{k.targetID, k.vantage}] = a.stats()
	}
	for i := range cells {
		if st, ok := byTargetVantage[aggKey{cells[i].TargetID, cells[i].Source}]; ok {
			cells[i].Samples = st.Samples
			cells[i].OkRate = st.OkRate
			cells[i].P50Ms = st.P50Ms
			cells[i].LossPct = st.LossPct
			cells[i].JitterMs = st.JitterMs
			cells[i].LastStatus = st.LastStatus
		}
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].Source != cells[j].Source {
			return cells[i].Source < cells[j].Source
		}
		return cells[i].Destination < cells[j].Destination
	})

	nodeOf := func(v string) MatrixNode {
		if v == domain.ProbeVantageCenter {
			return centerNode
		}
		if n, ok := nodeByAgent[strings.TrimPrefix(v, domain.ProbeVantageAgentPrefix)]; ok {
			return n
		}
		return MatrixNode{ID: v, Label: strings.TrimPrefix(v, domain.ProbeVantageAgentPrefix)}
	}
	ordered := func(set map[string]bool) []MatrixNode {
		out := make([]MatrixNode, 0, len(set))
		for v := range set {
			out = append(out, nodeOf(v))
		}
		// Center first (it is the hub), then agents alphabetically.
		sort.Slice(out, func(i, j int) bool {
			ci := out[i].ID == domain.ProbeVantageCenter
			cj := out[j].ID == domain.ProbeVantageCenter
			if ci != cj {
				return ci
			}
			return out[i].ID < out[j].ID
		})
		return out
	}

	return ProbeMatrix{
		WindowMinutes: windowMinutes,
		Sources:       ordered(sources),
		Destinations:  ordered(destinations),
		Cells:         cells,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}
