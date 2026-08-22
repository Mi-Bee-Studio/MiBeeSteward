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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"mibee-steward/internal/cidrutil"
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

	// networkCIDR is this agent's own configured network (cfg.Network.CIDR), used
	// for the agent-side boundary check (issue #19 Layer 2-agent). When non-nil,
	// a scan command whose targets fall outside it is rejected before execution
	// (complete = failed) — a friendly early failure that saves a wasted cross-
	// subnet scan and the bogus host data it would produce. nil (empty/invalid
	// config) → degrade-open: the center's Layer 2 check is the authoritative
	// backstop, so the agent skipping its own check doesn't weaken the system.
	networkCIDR *net.IPNet

	// runScan executes a "scan" command's payload (targets/timeout) and returns
	// a result summary or error. Injected by cmd/agent so the poller doesn't
	// depend on the runner package (avoids an import cycle: runner → store, and
	// this package already imports domain).
	runScan func(ctx context.Context, targets string, timeoutSec int) (string, error)

	// remoteOpsEnabled gates the ops command family (restart / config-reload /
	// logs-tail, #278). Off by default: the agent must explicitly opt in via
	// center.remote_ops_enabled in its config. Defense in depth on top of the
	// CENTER-side switch (agent_fleet.remote_ops_enabled) — either side alone
	// can keep ops commands from executing.
	remoteOpsEnabled bool
	// logRing supplies the last N log lines for "logs-tail" (nil → the command
	// fails with a hint). Injected by cmd/agent.
	logRing func() []string
	// restart re-execs the agent process. Injected by cmd/agent (syscall.Exec
	// of os.Args[0]) so this package stays testable.
	restart func(reason string)

	cancel context.CancelFunc
	done   chan struct{}
}

// NewCommandPoller constructs the poller. runScan is the scan-execution callback
// (the agent wires its scanRunner.Run into this). pollEvery ≤0 → 60s.
// networkCIDR is this agent's own network (cfg.Network.CIDR); empty/invalid
// disables the agent-side boundary check (degrade-open).
func NewCommandPoller(centerURL, authToken string, pollEvery time.Duration, networkCIDR string, runScan func(context.Context, string, int) (string, error), logger *slog.Logger) *CommandPoller {
	if logger == nil {
		logger = slog.Default()
	}
	if pollEvery <= 0 {
		pollEvery = 60 * time.Second
	}
	var parsed *net.IPNet
	if ipNet, err := cidrutil.ParseNetwork(networkCIDR); err == nil && ipNet != nil {
		parsed = ipNet
	} else if err != nil && !errors.Is(err, cidrutil.ErrEmptyCIDR) {
		logger.Warn("agent command poller: invalid network cidr in config; boundary check disabled",
			"cidr", networkCIDR, "error", err)
	}
	return &CommandPoller{
		centerURL:   centerURL,
		authToken:   authToken,
		client:      newCenterClient(15 * time.Second),
		pollEvery:   pollEvery,
		networkCIDR: parsed,
		runScan:     runScan,
		logger:      logger,
		done:        make(chan struct{}),
	}
}

// EnableRemoteOps opts the agent into executing ops commands (#278). logRing
// supplies recent log lines (logs-tail); restart re-execs the process
// (restart / config-reload — a reload is a restart in practice: config is
// consumed at construction time, so re-exec is the only faithful reload).
func (p *CommandPoller) EnableRemoteOps(logRing func() []string, restart func(reason string)) *CommandPoller {
	p.remoteOpsEnabled = true
	p.logRing = logRing
	p.restart = restart
	return p
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

// PollOnceForTest runs one poll synchronously (test hook — the real loop
// polls on its own goroutine).
func (p *CommandPoller) PollOnceForTest(ctx context.Context) { p.pollOnce(ctx) }

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
		// Agent-side boundary check (issue #19 Layer 2-agent): refuse to scan
		// targets outside this agent's own network. This is the friendly mirror
		// of the center's Layer 1 (dispatch) + Layer 2 (ingestion) checks — it
		// fails the command HERE rather than burning a cross-subnet scan whose
		// results the center would just drop. Degraded to a no-op (scan proceeds)
		// when no CIDR is configured, since the center's check still authorizes.
		if p.networkCIDR != nil {
			in, out, perr := cidrutil.PartitionTargets(sp.Targets, p.networkCIDR)
			if perr != nil {
				result = fmt.Sprintf(`{"error":"invalid targets: %s"}`, perr.Error())
				status = "failed"
				break
			}
			if len(out) > 0 {
				sample := out
				const maxSample = 8
				if len(sample) > maxSample {
					sample = append(append([]string{}, out[:maxSample]...), "...")
				}
				p.logger.Warn("agent command poller: rejected out-of-network scan command",
					"id", cmd.ID, "in", len(in), "out", len(out), "sample", sample)
				result = fmt.Sprintf(`{"error":"targets outside agent network: %s (%d of %d IPs out of network)"}`,
					strings.Join(sample, ","), len(out), len(in)+len(out))
				status = "failed"
				break
			}
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
	case "restart", "config-reload", "logs-tail":
		if !p.remoteOpsEnabled {
			result = `{"error":"remote ops commands are disabled on this agent (center.remote_ops_enabled)"}`
			status = "failed"
			break
		}
		switch cmd.Command {
		case "logs-tail":
			if p.logRing == nil {
				result = `{"error":"no log ring configured"}`
				status = "failed"
				break
			}
			lines := p.logRing()
			const maxLines = 50
			if len(lines) > maxLines {
				lines = lines[len(lines)-maxLines:]
			}
			// JSON-encode so multi-line logs survive the TEXT result column.
			resultJSON, err := json.Marshal(map[string]any{"lines": lines})
			if err != nil {
				result = fmt.Sprintf(`{"error":"%s"}`, err.Error())
				status = "failed"
			} else {
				result = string(resultJSON)
			}
		case "restart", "config-reload":
			if p.restart == nil {
				result = `{"error":"no restart hook configured"}`
				status = "failed"
				break
			}
			// Complete FIRST (with the pre-restart ack) so the center records
			// the outcome before the process image is replaced; the re-exec
			// races the POST otherwise. The agent's next report after coming
			// back is the real "it restarted" signal (fresh uptime).
			p.logger.Warn("agent command poller: re-executing agent", "id", cmd.ID, "command", cmd.Command)
			p.complete(ctx, cmd.ID, "done", fmt.Sprintf(`{"restarting":true,"command":%q}`, cmd.Command))
			go func() {
				// Give the complete POST a moment to flush, then replace.
				time.Sleep(500 * time.Millisecond)
				p.restart(cmd.Command)
			}()
			return
		}
	default:
		result = fmt.Sprintf(`{"error":"unknown command: %s"}`, cmd.Command)
		status = "failed"
	}
	p.logger.Info("command poller: command executed", "id", cmd.ID, "command", cmd.Command, "status", status)
	p.complete(ctx, cmd.ID, status, result)
}

// complete reports a command's outcome to the center.
func (p *CommandPoller) complete(ctx context.Context, id int64, status, result string) {
	completeReq, _ := json.Marshal(map[string]string{"status": status, "result": result})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/agents/commands/%d/complete", p.centerURL, id), bytes.NewReader(completeReq))
	req.Header.Set("Authorization", "Bearer "+p.authToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Warn("command poller: report result failed", "id", id, "error", err)
		return
	}
	resp.Body.Close()
}
