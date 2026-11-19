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
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// gatewayWorld: one agent bound to one network with one router device.
func gatewayWorld(t *testing.T) (*AgentCommandService, *db.Queries, *sql.DB, int64) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewAgentCommandService(queries, false, false)
	ctx := context.Background()

	cidr := "192.168.1.0/24"
	net, err := queries.CreateNetwork(ctx, db.CreateNetworkParams{Name: "lan-a", Cidr: &cidr})
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `UPDATE networks SET agent_id = ? WHERE id = ?`, "agent-a", net.ID)
	require.NoError(t, err)
	res, err := conn.ExecContext(ctx,
		`INSERT INTO devices (device_uuid, name, ip_address, type, network_id, status) VALUES ('uuid-router-a', 'router-a', '192.168.1.1', 'router', ?, 'online')`, net.ID)
	require.NoError(t, err)
	devID, err := res.LastInsertId()
	require.NoError(t, err)
	return svc, queries, conn, devID
}

// TestDispatchGatewayProbe: one command per agent, payload carries the
// enabled endpoints and the timeout, nothing else rides the channel.
func TestDispatchGatewayProbe(t *testing.T) {
	svc, queries, _, _ := gatewayWorld(t)

	sent, err := svc.DispatchGatewayProbe(context.Background(),
		[]string{"agent-a", "agent-b"}, []string{"stun.cloudflare.com:3478", "my-stun.example.com:3478"}, 1200)
	require.NoError(t, err)
	require.Equal(t, 2, sent)

	pending, err := queries.ListPendingAgentCommands(context.Background(), db.ListPendingAgentCommandsParams{AgentID: "agent-a", Limit: 10})
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "gateway_probe", pending[0].Command)
	var payload struct {
		Servers   []string `json:"servers"`
		TimeoutMS int      `json:"timeout_ms"`
	}
	require.NoError(t, json.Unmarshal([]byte(pending[0].Payload), &payload))
	require.Equal(t, []string{"stun.cloudflare.com:3478", "my-stun.example.com:3478"}, payload.Servers)
	require.Equal(t, 1200, payload.TimeoutMS)
}

// TestComplete_NormalizesUnknownStatus: the agent may report a status the
// schema does not know (a future command kind, a corrupted payload). Complete
// must fold it to "done" rather than persisting an unqueryable value, and it
// must survive a nil-free result pointer dance for an empty body.
func TestComplete_NormalizesUnknownStatus(t *testing.T) {
	svc, queries, _, _ := gatewayWorld(t)
	ctx := context.Background()

	cmd, err := svc.Enqueue(ctx, "agent-a", "gateway_probe", map[string]any{"servers": []string{"x"}})
	require.NoError(t, err)
	require.NoError(t, svc.Complete(ctx, cmd.ID, "weird-status", ""))

	got, err := queries.GetAgentCommand(ctx, cmd.ID)
	require.NoError(t, err)
	require.Equal(t, "done", got.Status, "unknown statuses fold to done")
}

// TestDispatchGatewayProbe_NoServers: an empty (or all-disabled) server list
// means the operator turned probing off — no command may be enqueued, so an
// agent never runs a probe with nothing to talk to.
func TestDispatchGatewayProbe_NoServers(t *testing.T) {
	svc, queries, _, _ := gatewayWorld(t)
	ctx := context.Background()

	sent, err := svc.DispatchGatewayProbe(ctx, []string{"agent-a", "agent-b"}, nil, 1200)
	require.NoError(t, err)
	require.Zero(t, sent)
	sent, err = svc.DispatchGatewayProbe(ctx, []string{"agent-a"}, []string{}, 1200)
	require.NoError(t, err)
	require.Zero(t, sent)

	pending, err := queries.ListPendingAgentCommands(ctx, db.ListPendingAgentCommandsParams{AgentID: "agent-a", Limit: 10})
	require.NoError(t, err)
	require.Empty(t, pending, "no command may reach the agent")
}

// TestIngestGatewayProbe: a completed gateway_probe lands the profile in the
// router's scan_attributes.gateway, preserving other attribute sections.
func TestIngestGatewayProbe(t *testing.T) {
	svc, queries, _, devID := gatewayWorld(t)
	ctx := context.Background()

	// Pre-existing engine attributes the ingest must preserve.
	preset := domain.ScanAttributes{Vendor: "iStoreOS", Hostname: "r68s"}
	marshaled, err := domain.MarshalScanAttributes(preset)
	require.NoError(t, err)
	require.NoError(t, queries.UpdateScanAttributes(ctx, db.UpdateScanAttributesParams{ScanAttributes: marshaled, ID: devID}))

	// Enqueue + complete.
	_, err = svc.DispatchGatewayProbe(ctx, []string{"agent-a"},
		[]string{"stun.cloudflare.com:3478"}, 1500)
	require.NoError(t, err)
	pending, err := queries.ListPendingAgentCommands(ctx, db.ListPendingAgentCommandsParams{AgentID: "agent-a", Limit: 10})
	require.NoError(t, err)
	require.Len(t, pending, 1)

	result := `{"checked_at":"2026-11-19T00:00:00Z","upnp_available":true,` +
		`"upnp_server":"http://192.168.1.1:5000/rootDesc.xml","wan_ip":"203.0.113.9",` +
		`"port_mapping_ok":true,"nat_mapping":"eim","public_ip":"203.0.113.9",` +
		`"stun_servers_seen":5,"hole_punch_viable":true,"note":""}`
	require.NoError(t, svc.Complete(ctx, pending[0].ID, "done", result))
	require.NoError(t, svc.IngestGatewayProbe(ctx, pending[0].ID, "done", result))

	dev, err := queries.GetDevice(ctx, devID)
	require.NoError(t, err)
	attrs, err := domain.UnmarshalScanAttributes(dev.ScanAttributes)
	require.NoError(t, err)
	require.NotNil(t, attrs.Gateway, "gateway profile recorded")
	require.Equal(t, "eim", attrs.Gateway.NATMapping)
	require.True(t, attrs.Gateway.UpnpAvailable)
	require.Equal(t, "203.0.113.9", attrs.Gateway.WanIP)
	require.Equal(t, 5, attrs.Gateway.StunServersSeen)
	require.True(t, attrs.Gateway.HolePunchViable)
	require.Equal(t, "iStoreOS", attrs.Vendor, "pre-existing attributes preserved")
	require.Equal(t, "r68s", attrs.Hostname)
}

// TestIngestGatewayProbe_Rejections: failed completions, unknown commands,
// non-gateway payloads and networks without routers are all no-ops.
func TestIngestGatewayProbe_Rejections(t *testing.T) {
	svc, queries, rawConn, devID := gatewayWorld(t)
	ctx := context.Background()

	result := `{"nat_mapping":"eim","upnp_available":true}`
	// failed status → skip
	require.NoError(t, svc.IngestGatewayProbe(ctx, 999, "failed", result))
	// unknown command id → skip
	require.NoError(t, svc.IngestGatewayProbe(ctx, 424242, "done", result))

	// A non-gateway command completes and is skipped by the ingest (raw row:
	// logs-tail is remote-ops-gated, the fixture keeps that switch off).
	ins, err := rawConn.ExecContext(ctx,
		`INSERT INTO agent_commands (agent_id, command, payload) VALUES ('agent-a', 'scan', '{}')`)
	require.NoError(t, err)
	cmdID, err := ins.LastInsertId()
	require.NoError(t, err)
	require.NoError(t, svc.Complete(ctx, cmdID, "done", `{"run_id":1}`))
	require.NoError(t, svc.IngestGatewayProbe(ctx, cmdID, "done", `{"run_id":1}`))

	// Garbage payload on a real gateway_probe command → skipped gracefully.
	gw, err := svc.Enqueue(ctx, "agent-a", "gateway_probe", map[string]any{"servers": []string{"x"}})
	require.NoError(t, err)
	require.NoError(t, svc.Complete(ctx, gw.ID, "done", "not-json"))
	require.NoError(t, svc.IngestGatewayProbe(ctx, gw.ID, "done", "not-json"))

	// Nothing landed anywhere.
	dev, err := queries.GetDevice(ctx, devID)
	require.NoError(t, err)
	if dev.ScanAttributes != "" {
		attrs, err := domain.UnmarshalScanAttributes(dev.ScanAttributes)
		require.NoError(t, err)
		require.Nil(t, attrs.Gateway)
	}
}

// TestIngestGatewayProbe_EmptyAndRoutless: a report with nothing to record
// (no NAT verdict, no UPnP, no WAN IP) and a network whose router row is gone
// are both silent no-ops — profile data is best-effort, never inventory.
func TestIngestGatewayProbe_EmptyAndRoutless(t *testing.T) {
	svc, _, rawConn, _ := gatewayWorld(t)
	ctx := context.Background()

	// Nothing to record: every profile field empty.
	gw, err := svc.Enqueue(ctx, "agent-a", "gateway_probe", map[string]any{"servers": []string{"x"}})
	require.NoError(t, err)
	empty := `{"checked_at":"","upnp_available":false,"upnp_server":"","wan_ip":""}`
	require.NoError(t, svc.Complete(ctx, gw.ID, "done", empty))
	require.NoError(t, svc.IngestGatewayProbe(ctx, gw.ID, "done", empty))

	// Router row removed: the ingest must not resurrect or crash.
	_, err = rawConn.ExecContext(ctx, `DELETE FROM devices`)
	require.NoError(t, err)
	gw2, err := svc.Enqueue(ctx, "agent-a", "gateway_probe", map[string]any{"servers": []string{"x"}})
	require.NoError(t, err)
	result := `{"nat_mapping":"edm","public_ip":"203.0.113.9"}`
	require.NoError(t, svc.Complete(ctx, gw2.ID, "done", result))
	require.NoError(t, svc.IngestGatewayProbe(ctx, gw2.ID, "done", result))

	var count int
	require.NoError(t, rawConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&count))
	require.Zero(t, count, "ingest must not create devices")
}
