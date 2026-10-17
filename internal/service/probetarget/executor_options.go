// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// Option-aware execution for the http and tcp modules (#605). The legacy
// option-less path stays on the shared probe.Prober implementations
// (heartbeat parity); these variants only run when the target carries an
// options block, so pre-#605 semantics are bit-for-bit unchanged.

// bodyReadLimit bounds how much of an HTTP body keyword matching inspects.
const bodyReadLimit = 1 << 20 // 1 MiB

// executeHTTPOptions runs the http module with an options block: explicit
// method, exact expected status codes, and a body keyword check. The TLS
// posture matches the center default (verify); ignore_tls_errors is the
// explicit opt-out for self-signed internal sites. https targets still get
// their certificate chain collected exactly like the legacy path.
func (x *targetExecutor) executeHTTPOptions(ctx context.Context, t db.ProbeTarget, opts *domain.ProbeOptions, timeout time.Duration) outcome {
	method := http.MethodGet
	if opts.Method == "HEAD" {
		method = http.MethodHead
	}
	transport := &http.Transport{
		// Mirror the shared prober's redirect budget (≤10).
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.IgnoreTLSErrors}, //nolint:gosec // explicit per-target opt-out
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, method, t.Target, nil)
	if err != nil {
		return outcome{Status: "fail", ErrMsg: err.Error()}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return outcome{Status: classifyError(err.Error()), Latency: time.Since(start), ErrMsg: err.Error()}
	}
	defer resp.Body.Close()

	out := outcome{Latency: time.Since(start), StatusCode: resp.StatusCode}
	if !statusExpected(opts.ExpectedStatus, resp.StatusCode) {
		out.Status = "fail"
		out.ErrMsg = fmt.Sprintf("http status %d not in expected set", resp.StatusCode)
		return x.withHTTPCerts(ctx, t, timeout, out)
	}

	if opts.Keyword != "" && method != http.MethodHead {
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, bodyReadLimit+1))
		if rerr != nil {
			out.Status = "fail"
			out.ErrMsg = "read body: " + rerr.Error()
			return x.withHTTPCerts(ctx, t, timeout, out)
		}
		ok, reason, merr := matchPayload(opts.KeywordMode, opts.Keyword, body)
		if merr != nil {
			out.Status = "fail"
			out.ErrMsg = merr.Error()
			return x.withHTTPCerts(ctx, t, timeout, out)
		}
		if !ok {
			out.Status = "fail"
			out.ErrMsg = reason
			return x.withHTTPCerts(ctx, t, timeout, out)
		}
	}
	out.Status = "success"
	return x.withHTTPCerts(ctx, t, timeout, out)
}

// withHTTPCerts folds the https certificate collection into an option-path
// outcome (same rules as the legacy path: collect on https, never flip the
// http verdict).
func (x *targetExecutor) withHTTPCerts(ctx context.Context, t db.ProbeTarget, timeout time.Duration, out outcome) outcome {
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

// statusExpected decides the status verdict: the explicit expected set when
// given, the legacy status<400 rule otherwise.
func statusExpected(expected []int, code int) bool {
	if len(expected) == 0 {
		return code < 400
	}
	for _, c := range expected {
		if code == c {
			return true
		}
	}
	return false
}

// matchPayload applies a keyword/expect mode to a payload. Returns a
// human-readable reason when the match fails.
func matchPayload(mode, pattern string, payload []byte) (bool, string, error) {
	switch mode {
	case "", domain.ProbeKeywordContains:
		if bytes.Contains(payload, []byte(pattern)) {
			return true, "", nil
		}
		return false, "body does not contain keyword", nil
	case domain.ProbeKeywordNotContains:
		if bytes.Contains(payload, []byte(pattern)) {
			return false, "body contains forbidden keyword", nil
		}
		return true, "", nil
	case domain.ProbeKeywordRegex:
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, "", fmt.Errorf("invalid regex: %w", err)
		}
		if re.Match(payload) {
			return true, "", nil
		}
		return false, "body does not match regex", nil
	default:
		return false, "", fmt.Errorf("unknown match mode %q", mode)
	}
}

// executeTCPOptions runs the tcp module with an options block: optional
// payload write right after connect, then a banner expectation matched
// against the first bytes read. Without expect, connect success is the
// verdict (same as the legacy prober).
func (x *targetExecutor) executeTCPOptions(ctx context.Context, t db.ProbeTarget, opts *domain.ProbeOptions, timeout time.Duration) outcome {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", t.Target)
	if err != nil {
		return outcome{Status: classifyError(err.Error()), Latency: time.Since(start), ErrMsg: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(timeout))

	if opts.Send != "" {
		if _, werr := conn.Write([]byte(opts.Send)); werr != nil {
			return outcome{Status: classifyError(werr.Error()), Latency: time.Since(start), ErrMsg: "write payload: " + werr.Error()}
		}
	}
	if opts.Expect != "" {
		buf := make([]byte, 4096)
		n, rerr := conn.Read(buf)
		if rerr != nil && n == 0 {
			return outcome{Status: classifyError(rerr.Error()), Latency: time.Since(start), ErrMsg: "read banner: " + rerr.Error()}
		}
		ok, reason, merr := matchPayload(opts.ExpectMode, opts.Expect, buf[:n])
		if merr != nil {
			return outcome{Status: "fail", Latency: time.Since(start), ErrMsg: merr.Error()}
		}
		if !ok {
			return outcome{Status: "fail", Latency: time.Since(start), ErrMsg: reason}
		}
	}
	return outcome{Status: "success", Latency: time.Since(start)}
}
