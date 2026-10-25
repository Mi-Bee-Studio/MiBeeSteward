// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package agentwatch declares agent liveness transitions (agent_offline /
// agent_recovered) from the fleet's last_report_at staleness, so a dead agent
// — which means a blind network segment in the distributed model — surfaces
// as a notification instead of silence. Events flow through the shared
// changedetect recorder like every other rule-eligible signal.
package agentwatch

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
)

const (
	// sweepInterval is how often staleness is re-evaluated.
	sweepInterval = 30 * time.Second
	// offlineThreshold is how stale last_report_at must be before an agent is
	// declared offline. The recommended probe cadence is 300s, so 10 minutes
	// tolerates two fully quiet cycles (a report lands with every probe round
	// AND every passive sweep) before declaring — generous against cadence
	// jitter, still timely for "the segment just went dark".
	offlineThreshold = 10 * time.Minute
)

// Sweeper is the agent-liveness state machine. First sight adopts the current
// staleness silently (a center restart must not synthesize a stale offline
// alert for an agent that was already dark); only later transitions emit.
type Sweeper struct {
	queries  *db.Queries
	recorder changedetect.ChangeRecorder
	logger   *slog.Logger

	mu      sync.Mutex
	offline map[string]bool // agentID → currently declared offline

	cancel  context.CancelFunc
	done    chan struct{}
	startMu sync.Mutex
	started bool
}

// NewSweeper builds a Sweeper. recorder may be nil (tests): transitions are
// detected but recorded nowhere.
func NewSweeper(queries *db.Queries, recorder changedetect.ChangeRecorder, logger *slog.Logger) *Sweeper {
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{
		queries:  queries,
		recorder: recorder,
		logger:   logger,
		offline:  make(map[string]bool),
		done:     make(chan struct{}),
	}
}

// Start launches the sweep loop (one immediate sweep, then every
// sweepInterval). A second call is a no-op.
func (s *Sweeper) Start(ctx context.Context) {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.started {
		return
	}
	s.started = true
	ctx, s.cancel = context.WithCancel(ctx)
	go s.run(ctx)
}

// Stop cancels the loop and waits for the in-flight sweep to settle.
func (s *Sweeper) Stop() {
	s.startMu.Lock()
	cancel := s.cancel
	started := s.started
	s.startMu.Unlock()
	if !started {
		return
	}
	if cancel != nil {
		cancel()
	}
	<-s.done
}

func (s *Sweeper) run(ctx context.Context) {
	defer close(s.done)
	s.sweep(ctx)
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

// sweep evaluates every known agent's staleness and emits transitions.
func (s *Sweeper) sweep(ctx context.Context) {
	rows, err := s.queries.ListAgentStatus(ctx)
	if err != nil {
		s.logger.Error("agent watch: list status failed", "error", err)
		return
	}

	now := time.Now()
	present := make(map[string]bool, len(rows))
	for _, row := range rows {
		present[row.AgentID] = true
		stale := now.Sub(row.LastReportAt) > offlineThreshold

		s.mu.Lock()
		prev, seen := s.offline[row.AgentID]
		if !seen {
			// First sight: adopt silently.
			s.offline[row.AgentID] = stale
			s.mu.Unlock()
			continue
		}
		s.offline[row.AgentID] = stale
		s.mu.Unlock()

		if stale == prev {
			continue // no transition
		}
		if s.recorder == nil {
			continue
		}
		changeType := changedetect.ChangeTypeAgentRecovered
		if stale {
			changeType = changedetect.ChangeTypeAgentOffline
		}
		s.recorder.Record(ctx, changedetect.ChangeEvent{
			ChangeType: changeType,
			EntityType: changedetect.EntityTypeAgent,
			AgentID:    row.AgentID,
			After: map[string]any{
				"agent_id":       row.AgentID,
				"hostname":       row.Hostname,
				"version":        row.Version,
				"last_report_at": row.LastReportAt.UTC().Format(time.RFC3339),
			},
		})
	}

	// Agents deregistered since last sweep drop their state.
	s.mu.Lock()
	for id := range s.offline {
		if !present[id] {
			delete(s.offline, id)
		}
	}
	s.mu.Unlock()
}
