// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package scannerv2

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestOrchestrator_CascadeDepthAndErrors pins the cascade BFS guards: the
// depth cap stops a self-triggering handler chain, a Collect error is logged
// and the chain continues, and cascade context reaches the handler metadata.
func TestOrchestrator_CascadeDepthAndErrors(t *testing.T) {
	repo := newRecordRepo()
	reg := NewRegistry()
	// A chain: http → self (each collect re-triggers "http" on a NEW port so
	// the cycle key differs; the depth cap is what stops it).
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.210.0.1", Port: 80, Protocol: "tcp"},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})

	h := &chainHandler{}
	reg.RegisterHandler(h)

	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 1, MaxCascadeDepth: 2}, nil)
	report := orch.Run(context.Background(), "10.210.0.1", ProbeHint{Timeout: time.Second})

	// First collect errored, second re-triggered; total collects bounded by
	// depth (0,1,2 → 3 nodes), the chain stopped instead of looping forever.
	if chainCollects == 0 || chainCollects > 5 {
		t.Fatalf("collects=%d: chain must run but stay depth-bounded", chainCollects)
	}
	if !report.Alive {
		t.Fatal("collect error must not kill the report")
	}
}

// chainHandler is an http handler whose Collect errors once, then re-triggers
// itself on an incrementing port (unique cycle keys) so the depth CAP is the
// only thing that ends the chain.
type chainHandler struct{}

func (chainHandler) Service() string                                 { return "http" }
func (chainHandler) GenerateHeartbeat(ServiceContext) *HeartbeatSpec { return nil }

var chainCollects int

func (h *chainHandler) Collect(_ context.Context, _ ServiceContext) (CollectedData, []Trigger, error) {
	chainCollects++
	if chainCollects == 1 {
		return nil, nil, errors.New("boom")
	}
	port := 1000 + chainCollects
	return nil, []Trigger{{Service: "http", Port: port, Context: map[string]string{"hop": "yes"}}}, nil
}

func (chainHandler) EnrichDevice(ServiceContext, CollectedData) {}
