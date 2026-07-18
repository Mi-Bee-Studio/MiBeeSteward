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
	"net/http"
	"time"
)

// HTTPProber sends HTTP/HTTPS GET requests to a target URL.
type HTTPProber struct{}

// Probe performs an HTTP GET to the target URL and checks the status code.
func (p *HTTPProber) Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		slog.Error("probe failed", "method", "http", "target", target, "error", err)
		return &Result{
			Success:      false,
			ErrorMessage: err.Error(),
		}, nil
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		slog.Error("probe failed", "method", "http", "target", target, "error", err)
		return &Result{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	latency := elapsed
	if success := resp.StatusCode < 400; success {
		slog.Debug("probe executed", "method", "http", "target", target, "success", true, "latency", latency)
		return &Result{
			Success: true,
			Latency: latency,
		}, nil
	}

	slog.Debug("probe executed", "method", "http", "target", target, "success", false, "latency", latency)
	return &Result{
		Success:      false,
		Latency:      latency,
		ErrorMessage: http.StatusText(resp.StatusCode),
	}, nil
}
