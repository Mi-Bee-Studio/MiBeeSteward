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

	"mibee-steward/internal/version"
)

// ProbeUserAgent is the User-Agent synthetic probes send. Some public sites
// reject common tool UAs outright: www.qq.com answers Go's default
// "Go-http-client/1.1" (and curl's) with 501 while a product UA gets 200,
// which kept the built-in egress-quality matrix permanently degraded on the
// center track (#713). Heartbeat deliberately does not use it (see
// HTTPProber.UserAgent).
func ProbeUserAgent() string {
	return "MiBeeSteward-probe/" + version.Version + " (+https://github.com/Mi-Bee-Studio/MiBeeSteward)"
}

// HTTPProber sends HTTP/HTTPS GET requests to a target URL. UserAgent, when
// set, replaces Go's default User-Agent header. The probe engine sets
// ProbeUserAgent(); heartbeat keeps the zero value so device checks against
// LAN web UIs stay exactly as before.
type HTTPProber struct {
	UserAgent string
}

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
		// execution failure against the target (dial/timeout/response) → streak log
		logProbeFailure("http", target, err)
		return &Result{
			Success:      false,
			ErrorMessage: err.Error(),
		}, nil
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		// execution failure against the target (dial/timeout/response) → streak
		// log. This is the branch a half-dead IoT http service hits EVERY cycle:
		// it stayed on direct slog.Error after #271 and a field center logged
		// ~2300 ERRORs/day from five such targets (2026-10-08).
		logProbeFailure("http", target, err)
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
		noteProbeSuccess("http", target, latency)
		return &Result{
			Success:    true,
			Latency:    latency,
			StatusCode: resp.StatusCode,
		}, nil
	}

	slog.Debug("probe executed", "method", "http", "target", target, "success", false, "latency", latency)
	return &Result{
		Success:      false,
		Latency:      latency,
		StatusCode:   resp.StatusCode,
		ErrorMessage: http.StatusText(resp.StatusCode),
	}, nil
}
