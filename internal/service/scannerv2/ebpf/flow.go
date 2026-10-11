// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Flow telemetry types (#500) — no build tag so the default build's CI
// unit-tests the shapes. The kernel side aggregates per
// (src, dst, proto, dport) into an LRU map (bpf/tc_ingress.c "flows"); the
// WITH_EBPF exporter drains it on a fixed cadence and hands whole batches to
// the late-bound sink. Raw per-port samples never persist anywhere: the
// service layer folds them into device-level speaks-with aggregates before
// anything reaches storage (the privacy red line of #500).

package ebpf

import "sync"

// FlowSample is one drained flow-map entry: the byte/packet totals observed
// for one (src -> dst, proto, dport) direction since the last drain.
type FlowSample struct {
	SrcIP  string
	DstIP  string
	Proto  uint16 // 6 = tcp, 17 = udp
	Dport  uint16
	Bytes  uint64
	Packets uint64
}

// FlowSink receives drained flow batches. It runs on the exporter goroutine
// and must be cheap (hand off, don't process).
type FlowSink func(samples []FlowSample)

var (
	flowMu   sync.Mutex
	flowSink FlowSink
)

// SetFlowSink binds the flow batch sink (late binding, mirroring
// SetHostSighting: the engine constructs before the flows service exists).
// A nil sink clears it. Safe to call before or after the observer started.
func SetFlowSink(fn FlowSink) {
	flowMu.Lock()
	flowSink = fn
	flowMu.Unlock()
}

// currentFlowSink returns the bound sink (nil when none).
func currentFlowSink() FlowSink {
	flowMu.Lock()
	defer flowMu.Unlock()
	return flowSink
}

// FlowExporterConfig controls the flow-map drain (see also Config.Flows).
// Defaults: every 30s, map capped at 16384 entries (~0.5 MiB kernel memory).
const (
	DefaultFlowExportIntervalSec = 30
	DefaultFlowMapEntries        = 16384
	MinFlowMapEntries            = 1024
	MaxFlowMapEntries            = 131072
)

// ClampFlowMapEntries bounds the LRU capacity to the supported range
// (power-of-two-ness is not required by the kernel for LRU_HASH; the clamp
// just keeps memory honest across config typos).
func ClampFlowMapEntries(n int) int {
	switch {
	case n <= 0:
		return DefaultFlowMapEntries
	case n < MinFlowMapEntries:
		return MinFlowMapEntries
	case n > MaxFlowMapEntries:
		return MaxFlowMapEntries
	default:
		return n
	}
}
