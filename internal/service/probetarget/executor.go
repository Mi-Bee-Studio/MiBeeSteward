// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/probe"
	"mibee-steward/internal/service/scannerv2"
)

// certCollector mirrors scannerv2probe.CollectCertChain's signature so tests
// can stub certificate collection without a real TLS endpoint. The production
// value IS the scanner's collector — the reuse that puts internal-network cert
// tooling to work on external hosts (hostname targets work as-is: SNI is
// auto-derived from the address).
type certCollector func(ctx context.Context, host string, port int, timeout time.Duration) []scannerv2.TLSCertRecord

// outcome is a single probe execution's result, before persistence. The cert
// summary fields mirror the probe_results summary columns (history without a
// join); certs carries the full chain for the probe_tls_certs upsert.
type outcome struct {
	status       string // success | fail | timeout
	latency      time.Duration
	statusCode   int // http module only
	errMsg       string
	tlsVersion   string
	certNotAfter string // leaf NotAfter, RFC3339; "" = none collected
	certTrusted  *bool
	certs        []scannerv2.TLSCertRecord // nil unless a chain was collected
}

// execute dispatches one target to its module prober. Never panics on an
// unknown module (returns a fail outcome) — the CHECK constraint makes that
// unreachable, but the engine must never wedge on bad data.
func (e *Engine) execute(ctx context.Context, t db.ProbeTarget) outcome {
	timeout := time.Duration(t.TimeoutSeconds) * time.Second
	switch t.Module {
	case "http":
		return e.executeHTTP(ctx, t, timeout)
	case "tls":
		return e.executeTLS(ctx, t, timeout)
	case "tcp":
		return e.executeSimple(ctx, t, "tcp", timeout)
	case "icmp":
		return e.executeSimple(ctx, t, "icmp", timeout)
	default:
		return outcome{status: "fail", errMsg: "unknown module: " + t.Module}
	}
}

// executeHTTP probes a full URL (status < 400 = success, ≤10 redirects — the
// shared HTTPProber's semantics, identical to heartbeat). For https targets it
// ALSO collects the certificate chain: the HTTP client verifies TLS, so an
// expired/untrusted cert fails the probe itself, while the skip-verify
// collector still captures the chain so the UI can show WHY it failed. A
// collection failure never flips an otherwise-successful HTTP probe — the cert
// fields are simply absent for that run.
func (e *Engine) executeHTTP(ctx context.Context, t db.ProbeTarget, timeout time.Duration) outcome {
	res, err := e.probers["http"].Probe(ctx, t.Target, timeout)
	if err != nil {
		// Prober-level error (not the target's fault) — counts as fail.
		return outcome{status: classifyError(err.Error()), errMsg: err.Error()}
	}
	out := outcomeFromResult(res)

	if u, perr := url.Parse(t.Target); perr == nil && u.Scheme == "https" {
		host := u.Hostname()
		port := 443
		if p := u.Port(); p != "" {
			if n, aerr := strconv.Atoi(p); aerr == nil {
				port = n
			}
		}
		out.attachCerts(e.collectCerts(ctx, host, port, timeout))
	}
	return out
}

// executeTLS is the pure certificate probe: handshake host:port, success =
// leaf record carries no Error. Latency wraps the whole collection call
// (two handshakes — collection + trust verdict), documented as such.
func (e *Engine) executeTLS(ctx context.Context, t db.ProbeTarget, timeout time.Duration) outcome {
	host, portStr, err := net.SplitHostPort(t.Target)
	if err != nil {
		return outcome{status: "fail", errMsg: "invalid target: " + err.Error()}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return outcome{status: "fail", errMsg: "invalid target port"}
	}

	start := time.Now()
	certs := e.collectCerts(ctx, host, port, timeout)
	out := outcome{latency: time.Since(start)}
	leaf := certs[0] // collectCerts guarantees ≥1 record
	if leaf.Error != "" {
		out.status = classifyError(leaf.Error)
		out.errMsg = leaf.Error
		return out
	}
	out.status = "success"
	out.tlsVersion = leaf.TLSVersion
	out.certNotAfter = leaf.NotAfter
	trusted := leaf.Trusted
	out.certTrusted = &trusted
	out.certs = certs
	return out
}

// executeSimple serves the tcp/icmp modules: straight passthrough to the
// shared probers (target grammar already validated at CRUD time).
func (e *Engine) executeSimple(ctx context.Context, t db.ProbeTarget, module string, timeout time.Duration) outcome {
	res, err := e.probers[module].Probe(ctx, t.Target, timeout)
	if err != nil {
		return outcome{status: classifyError(err.Error()), errMsg: err.Error()}
	}
	return outcomeFromResult(res)
}

// collectCerts wraps the injected collector, preserving CollectCertChain's
// ≥1-record invariant (error-only record on handshake failure) even if a test
// double forgets it.
func (e *Engine) collectCerts(ctx context.Context, host string, port int, timeout time.Duration) []scannerv2.TLSCertRecord {
	certs := e.certCollect(ctx, host, port, timeout)
	if len(certs) == 0 {
		return []scannerv2.TLSCertRecord{{IP: host, Port: port, Error: "tls handshake returned no records"}}
	}
	return certs
}

// attachCerts folds a collected chain into the outcome's summary fields.
// Only a successful collection applies; a failed one leaves the fields empty
// (the http verdict itself is authoritative for pass/fail).
func (o *outcome) attachCerts(certs []scannerv2.TLSCertRecord) {
	if len(certs) == 0 || certs[0].Error != "" {
		return
	}
	leaf := certs[0]
	o.tlsVersion = leaf.TLSVersion
	o.certNotAfter = leaf.NotAfter
	trusted := leaf.Trusted
	o.certTrusted = &trusted
	o.certs = certs
}

// outcomeFromResult maps a shared prober Result to an outcome.
func outcomeFromResult(res *probe.Result) outcome {
	out := outcome{
		latency:    res.Latency,
		statusCode: res.StatusCode,
	}
	if res.Success {
		out.status = "success"
		return out
	}
	out.status = classifyError(res.ErrorMessage)
	out.errMsg = res.ErrorMessage
	return out
}

// classifyError maps an error string to fail vs timeout. The shared probers
// don't distinguish (heartbeat only needs success/fail); probe_results has a
// third CHECK state and a dial timeout is operationally distinct from a
// refused connection, so match on the standard Go timeout error texts.
func classifyError(msg string) string {
	l := strings.ToLower(msg)
	if strings.Contains(l, "timeout") ||
		strings.Contains(l, "context deadline exceeded") ||
		strings.Contains(l, "request canceled") {
		return "timeout"
	}
	return "fail"
}
