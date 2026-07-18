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
	"fmt"
	"log/slog"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// ICMPProber sends ICMP ping requests to a target.
type ICMPProber struct{}

// Probe sends a single ICMP ping to the target and returns the result.
func (p *ICMPProber) Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error) {
	pinger, err := probing.NewPinger(target)
	if err != nil {
		slog.Error("probe failed", "method", "icmp", "target", target, "error", err)
		return &Result{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to create pinger: %v", err),
		}, nil
	}

	pinger.Timeout = timeout
	pinger.Count = 1
	pinger.SetPrivileged(false)

	start := time.Now()
	err = pinger.RunWithContext(ctx)
	elapsed := time.Since(start)

	if err != nil {
		slog.Error("probe failed", "method", "icmp", "target", target, "error", err)
		return &Result{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: err.Error(),
		}, nil
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 {
		slog.Debug("probe executed", "method", "icmp", "target", target, "success", true, "latency", stats.AvgRtt)
		return &Result{
			Success: true,
			Latency: stats.AvgRtt,
		}, nil
	}

	slog.Debug("probe executed", "method", "icmp", "target", target, "success", false, "latency", elapsed)
	return &Result{
		Success:      false,
		Latency:      elapsed,
		ErrorMessage: "no response received",
	}, nil
}
