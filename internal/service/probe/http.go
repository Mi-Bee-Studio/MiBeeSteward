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
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"mibee-steward/internal/version"
)

// UserAgent is the User-Agent synthetic probes send. Some public sites
// reject common tool UAs outright: www.qq.com answers Go's default
// "Go-http-client/1.1" (and curl's) with 501 while a product UA gets 200,
// which kept the built-in egress-quality matrix permanently degraded on the
// center track (#713). Heartbeat deliberately does not use it (see
// HTTPProber.UserAgent).
func UserAgent() string {
	return "MiBeeSteward-probe/" + version.Version + " (+https://github.com/Mi-Bee-Studio/MiBeeSteward)"
}

// HTTPProber sends HTTP/HTTPS GET requests to a target URL. UserAgent, when
// set, replaces Go's default User-Agent header. The probe engine fills it
// from UserAgent(); heartbeat keeps the zero value so device checks against
// LAN web UIs stay exactly as before.
type HTTPProber struct {
	UserAgent string
}

// Probe performs an HTTP GET to the target URL and checks the status code.
// tracedPhases bundles the exported per-stage numbers (#717) with the
// unexported timing anchors the httptrace hooks write into.
type tracedPhases struct {
	Phases
	dnsStart, connectStart, tlsStart, wroteReq time.Time
}

func (t *tracedPhases) msSince(start time.Time) float64 {
	if start.IsZero() {
		return 0
	}
	return float64(time.Since(start).Microseconds()) / 1000
}

func (p *HTTPProber) Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error) {
	// Per-stage timing (#717): the trace hooks fire inside client.Do; the
	// phases ride on every Result this function returns — failure results
	// keep the stages that DID complete (a timeout mid-handshake still tells
	// you what dns/connect cost).
	ph := &tracedPhases{}
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { ph.dnsStart = time.Now() },
		DNSDone:  func(httptrace.DNSDoneInfo) { ph.DNSMs = ph.msSince(ph.dnsStart) },
		ConnectStart: func(_, _ string) {
			if ph.connectStart.IsZero() {
				ph.connectStart = time.Now()
			}
		},
		ConnectDone: func(_, _ string, err error) {
			if err == nil && ph.ConnectMs == 0 {
				ph.ConnectMs = ph.msSince(ph.connectStart)
			}
		},
		TLSHandshakeStart: func() { ph.tlsStart = time.Now() },
		TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { ph.TLSMs = ph.msSince(ph.tlsStart) },
		GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				if host, _, err := net.SplitHostPort(info.Conn.RemoteAddr().String()); err == nil {
					ph.ResolvedIP = host
				} else {
					ph.ResolvedIP = info.Conn.RemoteAddr().String()
				}
			}
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { ph.wroteReq = time.Now() },
		GotFirstResponseByte: func() { ph.TTFBMs = ph.msSince(ph.wroteReq) },
	}
	traceCtx := httptrace.WithClientTrace(ctx, trace)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(traceCtx, http.MethodGet, target, nil)
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
			Phases:       &ph.Phases,
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
			Phases:     &ph.Phases,
		}, nil
	}

	slog.Debug("probe executed", "method", "http", "target", target, "success", false, "latency", latency)
	return &Result{
		Success:      false,
		Latency:      latency,
		StatusCode:   resp.StatusCode,
		ErrorMessage: http.StatusText(resp.StatusCode),
		Phases:       &ph.Phases,
	}, nil
}
