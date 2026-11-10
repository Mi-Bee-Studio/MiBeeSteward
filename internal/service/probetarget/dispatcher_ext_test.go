// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
)

// setupExtDispatch is setupDispatch with an injected probe config, for the
// egress/trace plan lanes (#718/#719).
func setupExtDispatch(t *testing.T, cfg config.ProbeConfig) (*AgentDispatcher, *fakeEnqueuer, *sql.DB) {
	t.Helper()
	d, fake, _, conn := setupDispatch(t)
	d.cfg = cfg
	return d, fake, conn
}

// TestAgentDispatch_EgressPlanLane pins the egress echo plan (#718):
// capability-gated, fingerprint-deduped, refreshed like probe plans, and
// cleared exactly once when the center disables egress.
func TestAgentDispatch_EgressPlanLane(t *testing.T) {
	cfg := config.ProbeConfig{}
	cfg.Egress.Enabled = true
	cfg.Egress.IntervalSeconds = 300
	cfg.Egress.Sources = config.DefaultEgressSources()
	d, fake, conn := setupExtDispatch(t, cfg)
	seedVantageWorld(t, conn)
	upsertCaps(t, conn, "agent-62", "icmp,http,tls,tcp,dns,egress")
	ctx := context.Background()

	// First tick: one probe plan + one egress plan; a second tick ships
	// neither again (steady state = zero traffic).
	d.DispatchTick(ctx)
	egress := fake.payloadsOf("agent-62", "egress")
	require.Len(t, egress, 1, "one egress plan on first tick")
	require.Len(t, egress[0]["sources"].([]config.ProbeEgressSource), len(config.DefaultEgressSources()))
	require.Equal(t, 300, egress[0]["interval_seconds"])
	require.NotEmpty(t, egress[0]["fingerprint"])
	d.DispatchTick(ctx)
	require.Len(t, fake.payloadsOf("agent-62", "egress"), 1)

	// Past the refresh window the plan re-ships (agent-restart recovery).
	d.lastEgressAt["agent-62"] = time.Now().Add(-planRefreshInterval - time.Second)
	d.DispatchTick(ctx)
	require.Len(t, fake.payloadsOf("agent-62", "egress"), 2, "refresh re-ships the egress plan")

	// A source-list change re-ships immediately (fingerprint covers content).
	cfg.Egress.Sources = cfg.Egress.Sources[:1]
	d.cfg = cfg
	d.DispatchTick(ctx)
	all := fake.payloadsOf("agent-62", "egress")
	require.Len(t, all, 3)
	require.Len(t, all[2]["sources"].([]config.ProbeEgressSource), 1)

	// Disabling egress sends exactly ONE clearing (empty-sources) plan.
	cfg.Egress.Enabled = false
	d.cfg = cfg
	d.DispatchTick(ctx)
	all = fake.payloadsOf("agent-62", "egress")
	require.Len(t, all, 4, "exactly one clearing plan")
	require.Empty(t, all[3]["sources"])
	d.DispatchTick(ctx)
	require.Len(t, fake.payloadsOf("agent-62", "egress"), 4, "no repeat clears")
}

// TestAgentDispatch_EgressCapabilityGate: an agent that never declared the
// egress capability receives no egress commands at all (old agents would only
// answer "unknown command").
func TestAgentDispatch_EgressCapabilityGate(t *testing.T) {
	cfg := config.ProbeConfig{}
	cfg.Egress.Enabled = true
	cfg.Egress.IntervalSeconds = 300
	cfg.Egress.Sources = config.DefaultEgressSources()
	d, fake, conn := setupExtDispatch(t, cfg)
	seedVantageWorld(t, conn)
	// Declared probe modules but NOT egress.
	upsertCaps(t, conn, "agent-62", "icmp,http,tls,tcp,dns")
	d.DispatchTick(context.Background())
	require.Empty(t, fake.payloadsOf("agent-62", "egress"), "no egress plan without the capability")
	require.NotEmpty(t, fake.payloadsOf("agent-62", "probe"), "probe plans unaffected")
}

// TestAgentDispatch_TraceBlock pins the trace schedule riding the probe plan
// (#719): shipped only to `trace`-capable agents, covered by the fingerprint
// (a trace-config change alone re-ships), and the specs carry their category.
func TestAgentDispatch_TraceBlock(t *testing.T) {
	cfg := config.ProbeConfig{}
	cfg.Trace.Categories = []string{"external"}
	cfg.Trace.IntervalMinutes = 30
	cfg.Trace.MaxTTL = 20
	cfg.Trace.PerHopMs = 400
	d, fake, conn := setupExtDispatch(t, cfg)
	seedVantageWorld(t, conn)
	ctx := context.Background()

	// Without the trace capability: probe plan, no trace key, but the specs
	// still carry their (manual → external) category.
	upsertCaps(t, conn, "agent-62", "icmp,http,tls,tcp,dns")
	d.DispatchTick(ctx)
	plan := fake.payloadsOf("agent-62", "probe")[0]
	require.NotContains(t, plan, "trace", "no trace block for a trace-incapable agent")
	for _, s := range plan["targets"].([]Spec) {
		require.Equal(t, "external", s.Category)
	}

	// Declaring trace: fingerprint changes, the re-shipped plan carries the block.
	upsertCaps(t, conn, "agent-62", "icmp,http,tls,tcp,dns,trace")
	d.DispatchTick(ctx)
	plan = fake.payloadsOf("agent-62", "probe")[1]
	trace, ok := plan["trace"].(*TracePlan)
	require.True(t, ok, "trace block present")
	require.Equal(t, []string{"external"}, trace.Categories)
	require.Equal(t, 20, trace.MaxTTL)
	require.Equal(t, 400, trace.PerHopMs)

	// Unchanged plan + unchanged trace: quiet.
	d.DispatchTick(ctx)
	require.Len(t, fake.payloadsOf("agent-62", "probe"), 2)

	// Trace-config change alone re-ships the plan.
	cfg.Trace.MaxTTL = 25
	d.cfg = cfg
	d.DispatchTick(ctx)
	plan = fake.payloadsOf("agent-62", "probe")[2]
	trace = plan["trace"].(*TracePlan)
	require.Equal(t, 25, trace.MaxTTL)
}

// TestPlanFingerprintTraceSensitivity: the fingerprint distinguishes nil
// trace from a trace plan and reflects trace-field edits.
func TestPlanFingerprintTraceSensitivity(t *testing.T) {
	specs := []Spec{{ID: 1, Name: "web", Module: "http", Target: "http://x.example/"}}
	base := PlanFingerprint(specs, nil)
	require.Equal(t, base, PlanFingerprint(specs, nil))
	withTrace := PlanFingerprint(specs, &TracePlan{Categories: []string{"external"}, IntervalMinutes: 30})
	require.NotEqual(t, base, withTrace)
	require.NotEqual(t, withTrace, PlanFingerprint(specs, &TracePlan{Categories: []string{"external"}, IntervalMinutes: 60}))
}
