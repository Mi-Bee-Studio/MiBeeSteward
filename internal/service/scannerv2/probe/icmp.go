// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"log/slog"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"mibee-steward/internal/service/scannerv2"
)

// ICMPProbe is the liveness probe: it sends one unprivileged ICMP ping and,
// on success, emits a single "echo" Evidence with the RTT in RawData. This
// Evidence is what makes the orchestrator consider the host Alive.
//
// Name: "active:icmp".
type ICMPProbe struct{}

// NewICMPProbe returns an ICMP liveness probe.
func NewICMPProbe() *ICMPProbe { return &ICMPProbe{} }

func (p *ICMPProbe) Name() string { return "active:icmp" }

// Probe pings ip once. hint.Timeout bounds the wait. A dead host yields no
// evidence (orchestrator marks it not-alive).
func (p *ICMPProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		slog.Debug("icmp: bad target", "ip", ip, "error", err)
		return nil, nil
	}
	pinger.Timeout = timeout
	pinger.Count = 1
	pinger.SetPrivileged(false)

	start := time.Now()
	if err := pinger.RunWithContext(ctx); err != nil {
		return nil, nil // not alive — no evidence
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return nil, nil
	}
	rttMs := stats.AvgRtt.Milliseconds()
	return []scannerv2.Evidence{{
		Source:     "active:icmp",
		Kind:       "echo",
		IP:         ip,
		Confidence: 1.0,
		RawData:    map[string]string{"rtt_ms": timeMsString(rttMs)},
		ObservedAt: start,
	}}, nil
}
