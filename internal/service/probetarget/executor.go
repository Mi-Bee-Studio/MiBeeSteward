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
	scannerv2probe "mibee-steward/internal/service/scannerv2/probe"
)

// certCollector mirrors scannerv2probe.CollectCertChain's signature so tests
// can stub certificate collection without a real TLS endpoint. The production
// value IS the scanner's collector — the reuse that puts internal-network cert
// tooling to work on external hosts (hostname targets work as-is: SNI is
// auto-derived from the address).
type certCollector func(ctx context.Context, host string, port int, timeout time.Duration) []scannerv2.TLSCertRecord

// Outcome is a single probe execution's result, before persistence. The cert
// summary fields mirror the probe_results summary columns (history without a
// join); certs carries the full chain for the probe_tls_certs upsert.
// Exported because the agent reuses the same executor for vantage probing
// (#277): the agent has no center DB, so it runs RunTarget and ships the
// outcome back over the command/report channel instead of persisting.
type Outcome struct {
	Status       string // success | fail | timeout
	Latency      time.Duration
	StatusCode   int // http module only
	ErrMsg       string
	TLSVersion   string
	CertNotAfter string // leaf NotAfter, RFC3339; "" = none collected
	CertTrusted  *bool
	Certs        []scannerv2.TLSCertRecord // nil unless a chain was collected
}

// outcome kept as a spelling alias so the engine-side call sites read
// naturally during the export migration.
type outcome = Outcome

// targetExecutor is the stateless module dispatcher: which probers to use and
// how to collect certificate chains. Split from Engine so the agent-side
// vantage prober (#277) reuses the exact execution core without the center DB.
type targetExecutor struct {
	probers     map[string]probe.Prober // http/tcp/icmp modules
	certCollect certCollector
}

// defaultTargetExecutor is what RunTarget (and the agent) use: the production
// probers + the scanner's real cert collector.
var defaultTargetExecutor = targetExecutor{
	probers: map[string]probe.Prober{
		"http": &probe.HTTPProber{},
		"tcp":  &probe.TCPProber{},
		"icmp": &probe.ICMPProber{},
	},
	certCollect: scannerv2probe.CollectCertChain,
}

// RunTarget dispatches one target to its module prober — the shared
// execution core used by BOTH the center engine and the agent-side vantage
// prober (#277). Never panics on an unknown module (returns a fail outcome)
// — the CHECK constraint makes that unreachable, but callers must never
// wedge on bad data.
func RunTarget(ctx context.Context, t db.ProbeTarget) Outcome {
	return defaultTargetExecutor.execute(ctx, t)
}

// execute dispatches one target to its module prober. Never panics on an
// unknown module (returns a fail outcome) — the CHECK constraint makes that
// unreachable, but the engine must never wedge on bad data.
func (x *targetExecutor) execute(ctx context.Context, t db.ProbeTarget) outcome {
	timeout := time.Duration(t.TimeoutSeconds) * time.Second
	switch t.Module {
	case "http":
		return x.executeHTTP(ctx, t, timeout)
	case "tls":
		return x.executeTLS(ctx, t, timeout)
	case "tcp":
		return x.executeSimple(ctx, t, "tcp", timeout)
	case "icmp":
		return x.executeSimple(ctx, t, "icmp", timeout)
	default:
		return outcome{Status: "fail", ErrMsg: "unknown module: " + t.Module}
	}
}

// executeHTTP probes a full URL (status < 400 = success, ≤10 redirects — the
// shared HTTPProber's semantics, identical to heartbeat). For https targets it
// ALSO collects the certificate chain: the HTTP client verifies TLS, so an
// expired/untrusted cert fails the probe itself, while the skip-verify
// collector still captures the chain so the UI can show WHY it failed. A
// collection failure never flips an otherwise-successful HTTP probe — the cert
// fields are simply absent for that run.
func (x *targetExecutor) executeHTTP(ctx context.Context, t db.ProbeTarget, timeout time.Duration) outcome {
	res, err := x.probers["http"].Probe(ctx, t.Target, timeout)
	if err != nil {
		// Prober-level error (not the target's fault) — counts as fail.
		return outcome{Status: classifyError(err.Error()), ErrMsg: err.Error()}
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
		out.attachCerts(x.collectCerts(ctx, host, port, timeout))
	}
	return out
}

// executeTLS is the pure certificate probe: handshake host:port, success =
// leaf record carries no Error. Latency wraps the whole collection call
// (two handshakes — collection + trust verdict), documented as such.
func (x *targetExecutor) executeTLS(ctx context.Context, t db.ProbeTarget, timeout time.Duration) outcome {
	host, portStr, err := net.SplitHostPort(t.Target)
	if err != nil {
		return outcome{Status: "fail", ErrMsg: "invalid target: " + err.Error()}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return outcome{Status: "fail", ErrMsg: "invalid target port"}
	}

	start := time.Now()
	certs := x.collectCerts(ctx, host, port, timeout)
	out := outcome{Latency: time.Since(start)}
	leaf := certs[0] // collectCerts guarantees ≥1 record
	if leaf.Error != "" {
		out.Status = classifyError(leaf.Error)
		out.ErrMsg = leaf.Error
		return out
	}
	out.Status = "success"
	out.TLSVersion = leaf.TLSVersion
	out.CertNotAfter = leaf.NotAfter
	trusted := leaf.Trusted
	out.CertTrusted = &trusted
	out.Certs = certs
	return out
}

// executeSimple serves the tcp/icmp modules: straight passthrough to the
// shared probers (target grammar already validated at CRUD time).
func (x *targetExecutor) executeSimple(ctx context.Context, t db.ProbeTarget, module string, timeout time.Duration) outcome {
	res, err := x.probers[module].Probe(ctx, t.Target, timeout)
	if err != nil {
		return outcome{Status: classifyError(err.Error()), ErrMsg: err.Error()}
	}
	return outcomeFromResult(res)
}

// collectCerts wraps the injected collector, preserving CollectCertChain's
// ≥1-record invariant (error-only record on handshake failure) even if a test
// double forgets it.
func (x *targetExecutor) collectCerts(ctx context.Context, host string, port int, timeout time.Duration) []scannerv2.TLSCertRecord {
	certs := x.certCollect(ctx, host, port, timeout)
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
	o.TLSVersion = leaf.TLSVersion
	o.CertNotAfter = leaf.NotAfter
	trusted := leaf.Trusted
	o.CertTrusted = &trusted
	o.Certs = certs
}

// outcomeFromResult maps a shared prober Result to an outcome.
func outcomeFromResult(res *probe.Result) outcome {
	out := outcome{
		Latency:    res.Latency,
		StatusCode: res.StatusCode,
	}
	if res.Success {
		out.Status = "success"
		return out
	}
	out.Status = classifyError(res.ErrorMessage)
	out.ErrMsg = res.ErrorMessage
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
