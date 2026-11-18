// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// Gateway probe plumbing (#752/#753): the center enqueues a `gateway_probe`
// command (STUN list from the probe.nat overlay, PUBLIC + user nodes only)
// and, on completion, lands the agent's evidence into the network's router
// device scan_attributes.gateway. Best-effort end to end: a failed probe or
// a missing router row logs and moves on — profile data, not inventory.
//
// Command-channel separation of concerns: no secret ever rides the payload
// (the STUN list is endpoints only), matching the probe.plan contract.

// DispatchGatewayProbe enqueues one gateway_probe command per agent in the
// list. Called from the probe.nat settings subscriber and at startup when
// the switch is on.
func (s *AgentCommandService) DispatchGatewayProbe(ctx context.Context, agents []string, servers []string, timeoutMS int) (int, error) {
	if len(servers) == 0 {
		return 0, nil
	}
	payload, err := json.Marshal(map[string]any{
		"servers":    servers,
		"timeout_ms": timeoutMS,
	})
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, agentID := range agents {
		if _, err := s.queries.CreateAgentCommand(ctx, db.CreateAgentCommandParams{
			AgentID: agentID,
			Command: "gateway_probe",
			Payload: string(payload),
		}); err != nil {
			slog.Warn("gateway probe: enqueue failed", "agent_id", agentID, "error", err)
			continue
		}
		sent++
	}
	return sent, nil
}

// gatewayReportPayload mirrors the agent-rs gateway.GatewayReport wire shape
// (snake_case, identical fields).
type gatewayReportPayload struct {
	CheckedAt       string `json:"checked_at"`
	UpnpAvailable   bool   `json:"upnp_available"`
	UpnpServer      string `json:"upnp_server"`
	WanIP           string `json:"wan_ip"`
	PortMappingOK   bool   `json:"port_mapping_ok"`
	NATMapping      string `json:"nat_mapping"`
	PublicIP        string `json:"public_ip"`
	StunServersSeen int    `json:"stun_servers_seen"`
	HolePunchViable bool   `json:"hole_punch_viable"`
	Note            string `json:"note"`
}

// IngestGatewayProbe consumes one gateway_probe completion: the command row
// identifies the reporting agent, the agent's network's primary router
// device receives the profile under scan_attributes.gateway. Read-modify-
// write preserves every other engine-owned attribute section.
func (s *AgentCommandService) IngestGatewayProbe(ctx context.Context, commandID int64, status, result string) error {
	if status != "done" || result == "" {
		return nil
	}
	cmd, err := s.queries.GetAgentCommand(ctx, commandID)
	if err != nil {
		return nil // row raced a cleanup; nothing to attribute
	}
	if cmd.Command != "gateway_probe" {
		return nil
	}
	var report gatewayReportPayload
	if err := json.Unmarshal([]byte(result), &report); err != nil {
		slog.Warn("gateway probe: result decode failed", "command_id", commandID, "error", err)
		return nil
	}
	if report.NATMapping == "" && !report.UpnpAvailable && report.WanIP == "" {
		return nil // nothing to record
	}

	net, err := s.queries.GetNetworkByAgentID(ctx, &cmd.AgentID)
	if err != nil || net.ID == 0 {
		slog.Debug("gateway probe: no network for agent", "agent_id", cmd.AgentID)
		return nil
	}
	gw, err := s.queries.GetGatewayDeviceForNetwork(ctx, &net.ID)
	if err != nil {
		slog.Debug("gateway probe: no router device in network", "network_id", net.ID)
		return nil
	}

	var attrs domain.ScanAttributes
	if gw.ScanAttributes != "" {
		attrs, _ = domain.UnmarshalScanAttributes(gw.ScanAttributes)
	}
	checked := report.CheckedAt
	if checked == "" {
		checked = time.Now().UTC().Format(time.RFC3339)
	}
	attrs.Gateway = &domain.GatewayProfile{
		CheckedAt:       checked,
		UpnpAvailable:   report.UpnpAvailable,
		UpnpServer:      report.UpnpServer,
		WanIP:           report.WanIP,
		PortMappingOK:   report.PortMappingOK,
		NATMapping:      report.NATMapping,
		PublicIP:        report.PublicIP,
		StunServersSeen: report.StunServersSeen,
		HolePunchViable: report.HolePunchViable,
		Note:            report.Note,
	}
	marshaled, err := domain.MarshalScanAttributes(attrs)
	if err != nil {
		slog.Warn("gateway probe: attribute marshal failed", "device_id", gw.ID, "error", err)
		return nil
	}
	if err := s.queries.UpdateScanAttributes(ctx, db.UpdateScanAttributesParams{
		ScanAttributes: marshaled,
		ID:             gw.ID,
	}); err != nil {
		slog.Warn("gateway probe: attribute write failed", "device_id", gw.ID, "error", err)
		return nil
	}
	slog.Info("gateway probe: profile recorded", "agent_id", cmd.AgentID, "device_id", gw.ID,
		"nat_mapping", report.NATMapping, "upnp", report.UpnpAvailable)
	return nil
}
