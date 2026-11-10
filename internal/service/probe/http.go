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
	"sync"
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
// unexported timing anchors the httptrace hooks write into. The hooks fire
// on DIFFERENT goroutines (WroteRequest from the request-writer goroutine,
// GotFirstResponseByte from the connection read loop — both observed racing
// the others under -race, CI 42750109723), so every touch is mutex-guarded.
type tracedPhases struct {
	mu sync.Mutex
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
		DNSStart: func(httptrace.DNSStartInfo) {
			ph.mu.Lock()
			ph.dnsStart = time.Now()
			ph.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			ph.mu.Lock()
			ph.DNSMs = ph.msSince(ph.dnsStart)
			ph.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			ph.mu.Lock()
			if ph.connectStart.IsZero() {
				ph.connectStart = time.Now()
			}
			ph.mu.Unlock()
		},
		ConnectDone: func(_, _ string, err error) {
			ph.mu.Lock()
			if err == nil && ph.ConnectMs == 0 {
				ph.ConnectMs = ph.msSince(ph.connectStart)
			}
			ph.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			ph.mu.Lock()
			ph.tlsStart = time.Now()
			ph.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			ph.mu.Lock()
			ph.TLSMs = ph.msSince(ph.tlsStart)
			ph.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			ph.mu.Lock()
			if !info.Reused {
				if host, _, err := net.SplitHostPort(info.Conn.RemoteAddr().String()); err == nil {
					ph.ResolvedIP = host
				} else {
					ph.ResolvedIP = info.Conn.RemoteAddr().String()
				}
			}
			ph.mu.Unlock()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			ph.mu.Lock()
			ph.wroteReq = time.Now()
			ph.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			ph.mu.Lock()
			ph.TTFBMs = ph.msSince(ph.wroteReq)
			ph.mu.Unlock()
		},
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

	// Snapshot the phases under the lock: the last hooks (GotFirstResponseByte
	// on the read loop) may interleave with Do returning on this goroutine.
	ph.mu.Lock()
	phases := ph.Phases
	ph.mu.Unlock()

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
			Phases:       &phases,
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
			Phases:     &phases,
		}, nil
	}

	slog.Debug("probe executed", "method", "http", "target", target, "success", false, "latency", latency)
	return &Result{
		Success:      false,
		Latency:      latency,
		StatusCode:   resp.StatusCode,
		ErrorMessage: http.StatusText(resp.StatusCode),
		Phases:       &phases,
	}, nil
}
