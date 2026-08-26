// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/probetarget"
)

// ProbePlanCommand is the payload of the center's "probe" command (#277):
// the full, sorted set of targets this agent should probe locally, plus the
// plan fingerprint (the agent logs it; re-application is idempotent because
// ApplyConfig replaces the whole plan).
type ProbePlanCommand struct {
	Targets     []probetarget.Spec `json:"targets"`
	Fingerprint string             `json:"fingerprint"`
}

// ResultPoster ships finished probe results to the center. One method, called
// from the prober's own goroutine; the production implementation batches +
// retries lightly, tests stub it.
type ResultPoster interface {
	Post(ctx context.Context, results []probetarget.AgentResultReport)
}

// HTTPResultPoster posts result batches to the center's
// POST /api/v1/agents/probe-report with the agent bearer token. A failed post
// is logged and the batch DROPPED — probe results are observations, not
// ledger entries; a lost sample is preferable to unbounded buffering on a
// tiny router. (The scan reporter keeps its buffer because scan reports ARE
// the asset ledger; probes are not.)
type HTTPResultPoster struct {
	CenterURL string
	Token     string
	Client    *http.Client
	Logger    *slog.Logger
}

// NewHTTPResultPoster builds the production poster: the shared HTTP client
// defaults (no timeout — per-probe deadlines already bounded execution).
func NewHTTPResultPoster(centerURL, token string, logger *slog.Logger) *HTTPResultPoster {
	if logger == nil {
		logger = slog.Default()
	}
	return &HTTPResultPoster{
		CenterURL: centerURL,
		Token:     token,
		Client:    &http.Client{},
		Logger:    logger,
	}
}

type probeReportPayload struct {
	Results []probetarget.AgentResultReport `json:"results"`
}

func (p *HTTPResultPoster) Post(ctx context.Context, results []probetarget.AgentResultReport) {
	if len(results) == 0 {
		return
	}
	body, err := json.Marshal(probeReportPayload{Results: results})
	if err != nil {
		p.Logger.Warn("probe poster: marshal failed", "error", err)
		return
	}
	url := p.CenterURL + "/api/v1/agents/probe-report"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		p.Logger.Warn("probe poster: build request failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := p.Client.Do(req)
	if err != nil {
		p.Logger.Warn("probe poster: post failed; batch dropped", "count", len(results), "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.Logger.Warn("probe poster: center rejected batch; dropped", "status", resp.StatusCode, "count", len(results))
	}
}

// Prober executes the center-assigned vantage probe plan on the agent (#277
// step 2). The center sends the WHOLE plan whenever it changes (fingerprint
// gating — steady state is no traffic); the agent runs each target on its own
// interval entirely locally, so probing survives center downtime and never
// adds per-probe command-channel load.
type Prober struct {
	poster ResultPoster
	logger *slog.Logger

	mu      sync.Mutex
	targets []probetarget.Spec
	applied string // last applied plan fingerprint

	cancel context.CancelFunc
	done   chan struct{}
	// reportBatch aggregates finished results; flushed every flushInterval or
	// when full — one HTTP post per batch instead of per probe.
	reportBatch chan probetarget.AgentResultReport
}

// NewProber starts the local probe loop. tickInterval must be ≤ the smallest
// supported interval (the center UI floor is 10s) so intervals schedule
// faithfully; it re-reads the plan each tick, making ApplyConfig effective
// within one tick.
func NewProber(poster ResultPoster, logger *slog.Logger) *Prober {
	if logger == nil {
		logger = slog.Default()
	}
	return &Prober{
		poster:      poster,
		logger:      logger,
		done:        make(chan struct{}),
		reportBatch: make(chan probetarget.AgentResultReport, 1024),
	}
}

// Start launches the scheduling + reporting loops. Call once after
// construction; Stop cancels both.
func (p *Prober) Start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	go p.scheduleLoop(ctx)
	go p.reportLoop(ctx)
}

// Stop cancels the loops and waits for both to wind down.
func (p *Prober) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	<-p.done
}

// ApplyConfig replaces the whole probe plan (called by the command poller on
// a "probe" command). An empty target list clears the plan — the center
// dispatches one final empty plan when a target set empties out.
func (p *Prober) ApplyConfig(cmd ProbePlanCommand) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = append([]probetarget.Spec(nil), cmd.Targets...)
	p.applied = cmd.Fingerprint
	p.logger.Info("probe plan applied", "targets", len(p.targets), "fingerprint", shortFP(cmd.Fingerprint))
}

// PlanFingerprint returns the fingerprint of the currently applied plan
// ("" when none was ever applied) — command-completion payloads echo it so
// the center can correlate acks with plans.
func (p *Prober) PlanFingerprint() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.applied
}

func (p *Prober) scheduleLoop(ctx context.Context) {
	defer close(p.done)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	nextDue := make(map[int64]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		p.mu.Lock()
		targets := append([]probetarget.Spec(nil), p.targets...)
		p.mu.Unlock()

		now := time.Now()
		live := make(map[int64]bool, len(targets))
		for _, t := range targets {
			live[t.ID] = true
			due, ok := nextDue[t.ID]
			if !ok {
				// First sight of this target: due immediately (a fresh plan
				// should produce a first sample fast, not after an interval).
				due = now
			}
			if now.Before(due) {
				continue
			}
			nextDue[t.ID] = now.Add(time.Duration(t.IntervalSeconds) * time.Second)
			go p.probeOne(ctx, t)
		}
		for id := range nextDue {
			if !live[id] {
				delete(nextDue, id)
			}
		}
	}
}

// probeOne runs a single target through the shared execution core and queues
// the result for batch reporting. Panics in a module prober are contained:
// one bad target must never wedge the loop.
func (p *Prober) probeOne(ctx context.Context, spec probetarget.Spec) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("prober: target panic recovered", "target_id", spec.ID, "panic", r)
		}
	}()
	t := db.ProbeTarget{
		ID:             spec.ID,
		Name:           spec.Name,
		Module:         spec.Module,
		Target:         spec.Target,
		TimeoutSeconds: int64(spec.TimeoutSeconds),
	}
	out := probetarget.RunTarget(ctx, t)

	report := probetarget.AgentResultReport{
		TargetID:     spec.ID,
		Vantage:      spec.Vantage,
		Status:       out.Status,
		LatencyMs:    float64(out.Latency.Microseconds()) / 1000.0,
		StatusCode:   out.StatusCode,
		ErrorMessage: out.ErrMsg,
		TLSVersion:   out.TLSVersion,
		CertNotAfter: out.CertNotAfter,
		CertTrusted:  out.CertTrusted,
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	select {
	case p.reportBatch <- report:
	default:
		p.logger.Warn("prober: report buffer full; result dropped", "target_id", spec.ID)
	}
}

// reportLoop drains the result batch channel: 10s flush cadence or a
// 32-result full batch, whichever comes first.
func (p *Prober) reportLoop(ctx context.Context) {
	const (
		flushEvery = 10 * time.Second
		batchMax   = 32
	)
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	buf := make([]probetarget.AgentResultReport, 0, batchMax)

	flush := func() {
		if len(buf) == 0 {
			return
		}
		p.poster.Post(ctx, buf)
		buf = buf[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case r := <-p.reportBatch:
			buf = append(buf, r)
			if len(buf) >= batchMax {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

// Ensure the fmt import stays referenced if log sites change.
var _ = fmt.Sprintf
