// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"mibee-steward/internal/cidrutil"
	"mibee-steward/internal/db"
)

// AgentCommandService is the write half of the center→agent command channel
// (issue #240: the agent_command handler was grandfathered charter debt). The
// agent-side reads (Poll) and the admin list view stay as handler
// passthroughs.
type AgentCommandService struct {
	queries *db.Queries
}

// NewAgentCommandService constructs an AgentCommandService.
func NewAgentCommandService(queries *db.Queries) *AgentCommandService {
	return &AgentCommandService{queries: queries}
}

var (
	// ErrAgentIDRequired maps to 400.
	ErrAgentIDRequired = errors.New("agent_id is required")
)

// BoundaryError is a scan-target network-boundary rejection (issue #19,
// Layer 1). It carries the human-readable reason verbatim — the offending
// IPs — so the handler can surface it as the 400 body unchanged.
type BoundaryError struct{ Reason string }

func (e *BoundaryError) Error() string { return e.Reason }

// Enqueue stores a command (currently "scan") for an agent to pick up on its
// next poll. For "scan" commands the requested targets must fall inside the
// agent's bound network CIDR — the earliest, cheapest defense against
// cross-subnet mis-dispatch (issue #19, Layer 1: exactly what let an agent
// scan the wrong subnet and strand 30 devices). A network with no CIDR
// configured degrades open with a warning (historical networks must not be
// locked out); out-of-network targets are a hard error.
func (s *AgentCommandService) Enqueue(ctx context.Context, agentID, command string, payload map[string]interface{}) (db.AgentCommand, error) {
	if agentID == "" {
		return db.AgentCommand{}, ErrAgentIDRequired
	}
	if command == "" {
		command = "scan"
	}
	// Boundary check only for scan commands — other command types (none
	// today, but the channel is extensible) carry no targets field.
	if command == "scan" {
		if reason := s.validateScanTargets(ctx, agentID, payload); reason != "" {
			return db.AgentCommand{}, &BoundaryError{Reason: reason}
		}
	}

	payloadBytes, _ := json.Marshal(payload)
	return s.queries.CreateAgentCommand(ctx, db.CreateAgentCommandParams{
		AgentID: agentID,
		Command: command,
		Payload: string(payloadBytes),
	})
}

// Ack transitions pending→acknowledged so the command isn't re-polled.
func (s *AgentCommandService) Ack(ctx context.Context, id int64) error {
	return s.queries.AckAgentCommand(ctx, id)
}

// Complete records a finished command's outcome ("done" | "failed"; anything
// else normalizes to "done" to match the historical handler semantics).
func (s *AgentCommandService) Complete(ctx context.Context, id int64, status, result string) error {
	if status != "done" && status != "failed" {
		status = "done"
	}
	return s.queries.CompleteAgentCommand(ctx, db.CompleteAgentCommandParams{
		Status: status,
		Result: &result,
		ID:     id,
	})
}

// validateScanTargets checks that a scan command's targets fall inside the
// agent's bound network. Returns "" when acceptable, or a human-readable
// reason (used verbatim as the 400 body) when it must be rejected. Missing /
// unresolvable / cidr-less networks degrade open with a warning.
func (s *AgentCommandService) validateScanTargets(ctx context.Context, agentID string, payload map[string]interface{}) string {
	rawTargets, _ := payload["targets"].(string)
	targets := strings.TrimSpace(rawTargets)
	if targets == "" {
		// Missing targets is the agent-command layer's own concern (the
		// poller rejects it as "missing targets"); not a CIDR issue.
		return ""
	}
	net, err := s.queries.GetNetworkByAgentID(ctx, &agentID)
	if err != nil {
		// No network bound to this agent_id — we can't validate, so allow +
		// warn; the agent itself rejects unreachable targets. Best-effort.
		slog.Warn("agent command: cannot resolve agent network for boundary check; allowing",
			"agent_id", agentID, "error", err)
		return ""
	}
	cidr := ""
	if net.Cidr != nil {
		cidr = *net.Cidr
	}
	ipNet, perr := cidrutil.ParseNetwork(cidr)
	if errors.Is(perr, cidrutil.ErrEmptyCIDR) {
		// Network exists but has no cidr configured — degrade-open + warn.
		// This is the gap the cidr-enforcement prerequisite (issue #19) closes.
		slog.Warn("agent command: agent network has no cidr; boundary check skipped",
			"agent_id", agentID, "network_id", net.ID, "network_name", net.Name)
		return ""
	}
	if perr != nil {
		// A configured-but-unparseable cidr is a data error worth surfacing.
		return "agent network has invalid cidr: " + cidr
	}
	in, out, perr := cidrutil.PartitionTargets(targets, ipNet)
	if perr != nil {
		return "invalid scan targets: " + perr.Error()
	}
	if len(out) > 0 {
		// Hard reject. Surface a sample of the offending IPs (capped to keep
		// the error body readable); the admin sees exactly what was rejected.
		sample := out
		const maxSample = 8
		if len(sample) > maxSample {
			sample = append(append([]string{}, out[:maxSample]...), "...")
		}
		return "scan targets are outside agent network " + net.Name + " (" + cidr + "): " +
			strings.Join(sample, ", ") + " (" + strconv.Itoa(len(out)) + " of " + strconv.Itoa(len(in)+len(out)) + " IPs out of network)"
	}
	return ""
}
