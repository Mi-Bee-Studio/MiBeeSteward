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
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/cidrutil"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// AgentCommandService is the write half of the center→agent command channel
// (issue #240: the agent_command handler was grandfathered charter debt). The
// agent-side reads (Poll) and the admin list view stay as handler
// passthroughs.
type AgentCommandService struct {
	queries          *db.Queries
	remoteOpsEnabled bool
	// allowReservedTargets mirrors scanner.allow_reserved_targets (#317 escape
	// hatch); softens only the reserved-range scan-target rejection.
	allowReservedTargets bool
}

// NewAgentCommandService constructs an AgentCommandService. remoteOpsEnabled
// is the center-side ops gate (#278): when false, enqueueing restart /
// config-reload / logs-tail fails with ErrRemoteOpsDisabled (403).
// allowReservedTargets mirrors scanner.allow_reserved_targets.
func NewAgentCommandService(queries *db.Queries, remoteOpsEnabled, allowReservedTargets bool) *AgentCommandService {
	return &AgentCommandService{queries: queries, remoteOpsEnabled: remoteOpsEnabled, allowReservedTargets: allowReservedTargets}
}

var (
	// ErrAgentIDRequired maps to 400.
	ErrAgentIDRequired = errors.New("agent_id is required")
	// ErrRemoteOpsDisabled maps to 403: ops commands are double-gated (#278) —
	// center switch (agent_fleet.remote_ops_enabled) AND agent opt-in
	// (center.remote_ops_enabled on the agent). This error is the center gate.
	ErrRemoteOpsDisabled = errors.New("remote ops commands are disabled on the center (agent_fleet.remote_ops_enabled)")
	// ErrUnknownCommand maps to 400: the command isn't in the whitelist.
	ErrUnknownCommand = errors.New("unknown command")
)

// OpsCommands are the remote-operations command family (#278): they act on
// the agent PROCESS (restart / reload / read logs), not on the network. They
// need both the center switch and the agent opt-in; scan remains always-on.
var OpsCommands = map[string]bool{
	"restart":       true,
	"config-reload": true,
	"logs-tail":     true,
}

// ValidCommands is the full enqueue whitelist (scan + gated ops family).
func ValidCommands() map[string]bool {
	return map[string]bool{
		"scan":          true,
		"probe":         true,
		"restart":       true,
		"config-reload": true,
		"logs-tail":     true,
	}
}

// IsOpsCommand reports whether a command belongs to the gated ops family.
func IsOpsCommand(command string) bool { return OpsCommands[command] }

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
	if !ValidCommands()[command] {
		return db.AgentCommand{}, fmt.Errorf("%w: %s", ErrUnknownCommand, command)
	}
	if IsOpsCommand(command) && !s.remoteOpsEnabled {
		return db.AgentCommand{}, ErrRemoteOpsDisabled
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
	// Reserved address space never yields a real LAN device. Check this
	// BEFORE the network-boundary lookup so even a cidr-less network (where
	// the boundary check degrades open) can't be told to scan loopback (#317).
	if rerr := cidrutil.ValidateTargetsFor(targets, s.allowReservedTargets); rerr != nil {
		return "invalid scan targets: " + rerr.Error()
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

// --- Fleet status (#278) ---

// UpsertAgentStatus refreshes the fleet snapshot from one report. clockOffset
// is precomputed by the caller (receive_time - scanned_at); meta may be nil
// for agents on older builds (keep zero values).
func (s *AgentCommandService) UpsertAgentStatus(ctx context.Context, agentID string, meta *domain.AgentMeta, clockOffset float64) error {
	var version, goVersion, hostname string
	var uptime, scans int64
	if meta != nil {
		version, goVersion, hostname = meta.Version, meta.GoVersion, meta.Hostname
		uptime, scans = meta.UptimeSec, meta.ScansTotal
	}
	return s.queries.UpsertAgentStatus(ctx, db.UpsertAgentStatusParams{
		AgentID:            agentID,
		Version:            version,
		GoVersion:          goVersion,
		Hostname:           hostname,
		UptimeSeconds:      uptime,
		ClockOffsetSeconds: clockOffset,
		ScansTotal:         scans,
		LastReportAt:       time.Now().UTC(),
	})
}

// ListAgentStatus returns all fleet snapshots, stalest first.
func (s *AgentCommandService) ListAgentStatus(ctx context.Context) ([]db.AgentStatus, error) {
	return s.queries.ListAgentStatus(ctx)
}
