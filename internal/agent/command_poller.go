// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// CommandPoller periodically fetches pending commands from the center and
// executes them. It is the agent-side half of the center→agent command channel
// (Phase 5c): the center enqueues a "scan" command via POST /agents/{id}/commands;
// the agent polls GET /agents/commands on this ticker, runs the scan, and reports
// the result back.
//
// Pull model: the agent fetches, so no inbound connection from the center is
// needed (fits agent-behind-NAT). The poll interval is deliberately longer than
// the report interval (commands are ad-hoc, not high-frequency).
type CommandPoller struct {
	centerURL string
	authToken string
	client    *http.Client
	pollEvery time.Duration
	logger    *slog.Logger

	// runScan executes a "scan" command's payload (targets/timeout) and returns
	// a result summary or error. Injected by cmd/agent so the poller doesn't
	// depend on the runner package (avoids an import cycle: runner → store, and
	// this package already imports domain).
	runScan func(ctx context.Context, targets string, timeoutSec int) (string, error)

	cancel context.CancelFunc
	done   chan struct{}
}

// NewCommandPoller constructs the poller. runScan is the scan-execution callback
// (the agent wires its scanRunner.Run into this). pollEvery ≤0 → 60s.
func NewCommandPoller(centerURL, authToken string, pollEvery time.Duration, runScan func(context.Context, string, int) (string, error), logger *slog.Logger) *CommandPoller {
	if logger == nil {
		logger = slog.Default()
	}
	if pollEvery <= 0 {
		pollEvery = 60 * time.Second
	}
	return &CommandPoller{
		centerURL: centerURL,
		authToken: authToken,
		client:    newCenterClient(15 * time.Second),
		pollEvery: pollEvery,
		runScan:   runScan,
		logger:    logger,
		done:      make(chan struct{}),
	}
}

// Start launches the poll loop.
func (p *CommandPoller) Start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	go func() {
		defer close(p.done)
		t := time.NewTicker(p.pollEvery)
		defer t.Stop()
		// Poll once immediately on start (don't wait a full interval for the
		// first check).
		p.pollOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.pollOnce(ctx)
			}
		}
	}()
}

// Stop cancels the poll loop and waits for it to exit.
func (p *CommandPoller) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	<-p.done
}

// pendingCommand mirrors the center's agent_commands row (subset the poller needs).
// Payload is the raw TEXT column value (a JSON string like
// `{"targets":"192.168.62.0/24","timeout":300}`). The center stores it as TEXT
// and serializes it as a JSON string in the HTTP response, so the poller decodes
// it into a Go string here and unmarshals the string body into a typed struct in
// execute(). Using json.RawMessage would fail: the response carries a JSON string
// literal, not a bare object, so RawMessage would hold the quoted form and the
// subsequent Unmarshal into a struct would hit "cannot unmarshal string".
type pendingCommand struct {
	ID      int64  `json:"id"`
	Command string `json:"command"`
	Payload string `json:"payload"`
}

// scanPayload is the JSON payload of a "scan" command.
type scanPayload struct {
	Targets    string `json:"targets"`
	Timeout    int    `json:"timeout"`
	Concurrent int    `json:"concurrent"`
}

func (p *CommandPoller) pollOnce(ctx context.Context) {
	cmds, err := p.fetchPending(ctx)
	if err != nil {
		// Non-fatal: the center may be briefly unreachable. The reporter's
		// pending queue handles data; commands are ad-hoc and will be re-polled.
		p.logger.Debug("command poller: fetch failed", "error", err)
		return
	}
	for _, cmd := range cmds {
		// Ack first so it isn't re-polled if execution is slow.
		if err := p.ack(ctx, cmd.ID); err != nil {
			p.logger.Warn("command poller: ack failed", "id", cmd.ID, "error", err)
			continue
		}
		go p.execute(ctx, cmd)
	}
}

func (p *CommandPoller) fetchPending(ctx context.Context) ([]pendingCommand, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.centerURL+"/api/v1/agents/commands", nil)
	req.Header.Set("Authorization", "Bearer "+p.authToken)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var cmds []pendingCommand
	if err := json.NewDecoder(resp.Body).Decode(&cmds); err != nil {
		return nil, err
	}
	return cmds, nil
}

func (p *CommandPoller) ack(ctx context.Context, id int64) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/agents/commands/%d/ack", p.centerURL, id), nil)
	req.Header.Set("Authorization", "Bearer "+p.authToken)
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (p *CommandPoller) execute(ctx context.Context, cmd pendingCommand) {
	var result string
	status := "done"
	switch cmd.Command {
	case "scan":
		var sp scanPayload
		if err := json.Unmarshal([]byte(cmd.Payload), &sp); err != nil {
			result = fmt.Sprintf(`{"error":"bad payload: %s"}`, err.Error())
			status = "failed"
			break
		}
		if sp.Targets == "" {
			result = `{"error":"missing targets"}`
			status = "failed"
			break
		}
		// Bound the scan with a hard deadline so a stuck probe (e.g. an HTTP
		// read that hangs on an unresponsive host) can't block the execute
		// goroutine forever. sp.Timeout is the per-host pipeline timeout; the
		// scan fans out across hosts concurrently so we allow generous headroom
		// beyond it. Previously this used context.Background() (no deadline),
		// which meant one hung TCP read on a misbehaving camera left the command
		// in "acknowledged" forever — the device fleet then went offline as
		// leases expired with no fresh reports.
		deadline := 15 * time.Minute
		if sp.Timeout > 0 {
			deadline = time.Duration(sp.Timeout*2+60) * time.Second
		}
		scanCtx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		summary, err := p.runScan(scanCtx, sp.Targets, sp.Timeout)
		if err != nil {
			result = fmt.Sprintf(`{"error":"%s"}`, err.Error())
			status = "failed"
		} else {
			result = summary
		}
	default:
		result = fmt.Sprintf(`{"error":"unknown command: %s"}`, cmd.Command)
		status = "failed"
	}
	p.logger.Info("command poller: command executed", "id", cmd.ID, "command", cmd.Command, "status", status)

	// Report the result back to the center.
	completeReq, _ := json.Marshal(map[string]string{"status": status, "result": result})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/agents/commands/%d/complete", p.centerURL, cmd.ID), bytes.NewReader(completeReq))
	req.Header.Set("Authorization", "Bearer "+p.authToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Warn("command poller: report result failed", "id", cmd.ID, "error", err)
		return
	}
	resp.Body.Close()
}
