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
	"net"
	"time"
)

// TCPProber checks TCP port connectivity to a target address.
type TCPProber struct{}

// Probe attempts to establish a TCP connection to the target within the given timeout.
func (p *TCPProber) Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error) {
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	elapsed := time.Since(start)

	if err != nil {
		slog.Error("probe failed", "method", "tcp", "target", target, "error", err)
		return &Result{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: err.Error(),
		}, nil
	}
	conn.Close()

	slog.Debug("probe executed", "method", "tcp", "target", target, "success", true, "latency", elapsed)
	return &Result{
		Success: true,
		Latency: elapsed,
	}, nil
}
