// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// seedCapabilityWorld: one agent-bound network with a tcp and an http target
// on 'all' vantage, so module filtering decides what the agent receives.
func seedCapabilityWorld(t *testing.T, conn *sql.DB) {
	t.Helper()
	ctx := context.Background()
	_, err := conn.ExecContext(ctx, `INSERT INTO networks (id, name, cidr, agent_id) VALUES (5, 'lan-x', '192.168.2.0/24', 'agent-x')`)
	require.NoError(t, err)
	mk := func(name, module, target string) {
		_, err := conn.ExecContext(ctx,
			`INSERT INTO probe_targets (name, module, target, vantage, interval_seconds, timeout_seconds, enabled)
			 VALUES (?, ?, ?, 'all', 60, 10, 1)`, name, module, target)
		require.NoError(t, err)
	}
	mk("web", "http", "http://www.example.org/")
	mk("port", "tcp", "203.0.113.10:53")
	mk("resolve", "dns", "example.com")
}

func upsertCaps(t *testing.T, conn *sql.DB, agentID, modules string) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO agent_status (agent_id, version, supported_modules, last_report_at)
		 VALUES (?, 'mibee-agent-rs/0.2.0', ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(agent_id) DO UPDATE SET supported_modules = excluded.supported_modules`,
		agentID, modules)
	require.NoError(t, err)
}

// TestAgentDispatch_CapabilityFilter pins the module capability gate (#604):
// a legacy agent (no declaration) gets only the historical icmp/http/tls set,
// and a declared agent receives exactly its declared modules.
func TestAgentDispatch_CapabilityFilter(t *testing.T) {
	d, fake, _, conn := setupDispatch(t)
	seedCapabilityWorld(t, conn)
	ctx := context.Background()

	// Legacy agent: no agent_status row at all → historical set, tcp/dns held
	// back (the live fix for the "unknown module tcp" agent bug).
	d.DispatchTick(ctx)
	plan := fake.plans["agent-x"][0]["targets"].([]Spec)
	require.Len(t, plan, 1, "legacy agent receives only http")
	require.Equal(t, "http", plan[0].Module)

	// Upgrade path: the first report carries tcp+dns → full plan ships.
	upsertCaps(t, conn, "agent-x", "icmp,http,tls,tcp,dns")
	d.DispatchTick(ctx)
	plan = fake.plans["agent-x"][1]["targets"].([]Spec)
	require.Len(t, plan, 3)
	mods := map[string]bool{}
	for _, s := range plan {
		mods[s.Module] = true
	}
	require.True(t, mods["http"] && mods["tcp"] && mods["dns"])

	// A narrower declaration (agent without dns) sheds just that module.
	upsertCaps(t, conn, "agent-x", "icmp,http,tls,tcp")
	d.DispatchTick(ctx)
	plan = fake.plans["agent-x"][2]["targets"].([]Spec)
	require.Len(t, plan, 2)
}

// TestAgentDispatch_SpecCarriesOptions pins that an options block rides the
// wire spec verbatim (raw JSON) and changes the plan fingerprint.
func TestAgentDispatch_SpecCarriesOptions(t *testing.T) {
	d, fake, _, conn := setupDispatch(t)
	seedCapabilityWorld(t, conn)
	upsertCaps(t, conn, "agent-x", "http,tcp,dns")
	ctx := context.Background()

	d.DispatchTick(ctx)
	plan := fake.plans["agent-x"][0]["targets"].([]Spec)
	require.Empty(t, plan[0].Options, "option-less target omits the field")

	// Set options on the http target: fingerprint changes, plan re-ships with
	// the raw JSON attached.
	_, err := conn.ExecContext(ctx,
		`UPDATE probe_targets SET options = ? WHERE name = 'web'`,
		`{"keyword":"ok","keyword_mode":"contains"}`)
	require.NoError(t, err)
	d.lastSentAt["agent-x"] = time.Now().Add(-planRefreshInterval - time.Second)
	d.DispatchTick(ctx)
	plan = fake.plans["agent-x"][1]["targets"].([]Spec)
	var found bool
	for _, s := range plan {
		if s.Module == "http" {
			found = true
			require.JSONEq(t, `{"keyword":"ok","keyword_mode":"contains"}`, string(s.Options))
		}
	}
	require.True(t, found, "http spec present after options edit")
}
