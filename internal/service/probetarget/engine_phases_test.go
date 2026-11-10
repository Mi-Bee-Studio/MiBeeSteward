// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/probe"
	"mibee-steward/internal/testutil"
)

// fakePhasesSink captures StorePhase calls for the #717 wiring assertions.
type fakePhasesSink struct {
	mu    sync.Mutex
	calls []capturedPhase
}

type capturedPhase struct {
	targetID  int64
	module    string
	vantage   string
	checkedAt string
	latencyMs float64
	ph        *probe.Phases
}

func (f *fakePhasesSink) StorePhase(_ context.Context, targetID int64, module, vantage, checkedAt string, latencyMs float64, ph *probe.Phases) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, capturedPhase{targetID, module, vantage, checkedAt, latencyMs, ph})
	return nil
}

// TestEngine_PhasesSink pins the #717 flow: a result carrying phase data
// lands in the sink exactly once, tagged center; a result without phases
// (nil or empty) never does.
func TestEngine_PhasesSink(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)

	fp := &fakeProber{fn: func(call int) (*probe.Result, error) {
		if call == 1 {
			return &probe.Result{Success: true, StatusCode: 200, Latency: 30 * time.Millisecond,
				Phases: &probe.Phases{ResolvedIP: "192.0.2.7", DNSMs: 3, ConnectMs: 9, TLSMs: 12, TTFBMs: 5}}, nil
		}
		// Second call: success but no stage measured (dns module shape).
		return &probe.Result{Success: true, StatusCode: 200, Latency: time.Millisecond}, nil
	}}
	engine := newTestEngine(t, queries, fp, nil)
	sink := &fakePhasesSink{}
	engine.WithPhasesSink(sink)
	svc := New(queries, engine)
	ctx := context.Background()

	tgt := mustCreate(t, svc, validCreate("http", "http://x.example/"))

	_, err = engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
	require.Len(t, sink.calls, 1)
	c := sink.calls[0]
	require.Equal(t, tgt.ID, c.targetID)
	require.Equal(t, "http", c.module)
	require.Equal(t, domain.ProbeVantageCenter, c.vantage)
	require.Equal(t, 30.0, c.latencyMs)
	require.Equal(t, "192.0.2.7", c.ph.ResolvedIP)

	// Phase-less results never reach the sink.
	_, err = engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
	require.Len(t, sink.calls, 1, "phase-less result must not be stored")

	// No sink attached: the engine path still runs clean (nil-safe gate).
	engine.phases = nil
	fp.fn = func(int) (*probe.Result, error) {
		return &probe.Result{Success: true, StatusCode: 200, Latency: time.Millisecond,
			Phases: &probe.Phases{ResolvedIP: "192.0.2.8"}}, nil
	}
	_, err = engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
}

// TestIngestAgentResults_Phases: agent-reported phases land in the SAME sink
// under the reporting agent's vantage, with the module re-derived from the
// target lookup (the wire payload carries no module to spoof).
func TestIngestAgentResults_Phases(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := NewEngine(queries, quiet, nil, 0, nil)
	sink := &fakePhasesSink{}
	engine.WithPhasesSink(sink)
	svc := New(queries, engine)
	ctx := context.Background()

	created, err := svc.Create(ctx, validCreate("tcp", "x.example:443"))
	require.NoError(t, err)

	n, err := svc.IngestAgentResults(ctx, "agent-62", []AgentResultReport{
		{TargetID: created.ID, Status: "success", LatencyMs: 42, CheckedAt: "2026-11-09T02:00:00Z",
			Phases: &probe.Phases{ResolvedIP: "203.0.113.5", ConnectMs: 41}},
	})
	require.NoError(t, err)
	require.Equal(t, 1, n)

	require.Len(t, sink.calls, 1)
	c := sink.calls[0]
	require.Equal(t, created.ID, c.targetID)
	require.Equal(t, "tcp", c.module, "module must come from the target, not the report")
	require.Equal(t, domain.ProbeVantageAgentPrefix+"agent-62", c.vantage)
	require.Equal(t, "2026-11-09T02:00:00Z", c.checkedAt)
	require.Equal(t, 42.0, c.latencyMs)

	// Report without phases: no sink call.
	n, err = svc.IngestAgentResults(ctx, "agent-62", []AgentResultReport{
		{TargetID: created.ID, Status: "success", LatencyMs: 7, CheckedAt: "2026-11-09T02:01:00Z"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Len(t, sink.calls, 1)
}
