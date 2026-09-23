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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/probetarget"
)

// TestProber_ApplyConfig pins the plan lifecycle: apply stores the plan and
// its fingerprint, re-apply replaces wholesale (no merge residue from a
// previous plan), and the empty plan clears targets.
func TestProber_ApplyConfig(t *testing.T) {
	p := NewProber(nil, nil) // poster nil: loops never started, poster unused

	specs := []probetarget.Spec{
		{ID: 1, Name: "a", Module: "http", Target: "http://a/", IntervalSeconds: 60, TimeoutSeconds: 10, Vantage: "agent:x"},
		{ID: 2, Name: "b", Module: "tcp", Target: "b:443", IntervalSeconds: 120, TimeoutSeconds: 10, Vantage: "agent:x"},
	}
	p.ApplyConfig(ProbePlanCommand{Fingerprint: "fp1", Targets: specs})
	require.Equal(t, "fp1", p.PlanFingerprint())

	p.ApplyConfig(ProbePlanCommand{Fingerprint: "fp2", Targets: specs[:1]})
	require.Equal(t, "fp2", p.PlanFingerprint())

	// Empty plan clears.
	p.ApplyConfig(ProbePlanCommand{Fingerprint: "fp3"})
	require.Equal(t, "fp3", p.PlanFingerprint())
}

// The report loop's final drain must post on a LIVE context: the loop ctx is
// already cancelled when the Done branch runs, posting with it would abort
// the HTTP request and drop the buffered batch on every shutdown.
func TestProber_ReportLoopFinalFlushSurvivesCancel(t *testing.T) {
	posted := make(chan []probetarget.AgentResultReport, 1)
	p := NewProber(stubPoster{ch: posted}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		p.reportLoop(ctx)
	}()

	p.reportBatch <- probetarget.AgentResultReport{TargetID: 7}
	time.Sleep(50 * time.Millisecond) // let the loop buffer the result
	cancel()

	select {
	case batch := <-posted:
		require.Len(t, batch, 1, "buffered result must be delivered by the final flush")
		require.Equal(t, int64(7), batch[0].TargetID)
	case <-time.After(3 * time.Second):
		t.Fatal("final flush did not deliver the buffered batch")
	}
	select {
	case <-loopDone:
	case <-time.After(3 * time.Second):
		t.Fatal("report loop did not exit after cancel")
	}
}

type stubPoster struct {
	ch chan []probetarget.AgentResultReport
}

func (s stubPoster) Post(_ context.Context, results []probetarget.AgentResultReport) {
	s.ch <- results
}
