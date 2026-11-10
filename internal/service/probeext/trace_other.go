// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

//go:build !linux

package probeext

import (
	"context"
	"time"
)

// Tracer is the non-Linux stub: the product targets Linux, and the TTL
// socket options involved are Linux-only. Dev machines (Windows) get a
// polite error instead of a build break.
type Tracer struct {
	MaxTTL   int
	PerHop   time.Duration
	Attempts int
}

// NewTracer mirrors the Linux constructor.
func NewTracer(maxTTL, perHopMs, attempts int) *Tracer {
	return &Tracer{MaxTTL: maxTTL, PerHop: time.Duration(perHopMs) * time.Millisecond, Attempts: attempts}
}

// TraceResult mirrors the Linux shape.
type TraceResult struct {
	Method     string
	DstIP      string
	Hops       []PathHop
	EndState   string
	ReachedTTL int
	ReplyTTL   int
	Err        string
}

// TraceHost always reports unsupported on non-Linux builds.
func (t *Tracer) TraceHost(_ context.Context, host string, _ int, method string) TraceResult {
	return TraceResult{Method: method, EndState: "error",
		Err: "path tracing is only supported on Linux (got host " + host + ")"}
}
