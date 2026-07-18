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
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// httpProbeReadLimit bounds how much of an HTTP response body we read for
// title/header extraction. 64KB is enough for virtually every admin/index page
// without wasting bandwidth on large downloads.
const httpProbeReadLimit = 64 * 1024

// httpProbeTimeout bounds a single HTTP GET (dial + headers + body read). Kept
// short since we only want the title/headers; a slow server shouldn't block
// the scan.
const httpProbeTimeout = 4 * time.Second

// httpProbePorts is the set of ports the HTTP probe runs against. Other ports
// are left to the port scan's GET / active-probe string (banners.go), which
// captures the response into a generic banner evidence — this dedicated probe
// instead extracts structured fields (title, server, x-powered-by).
var httpProbePorts = map[int]bool{
	80: true, 8080: true, 8000: true, 8008: true, 8081: true, 8888: true,
	9000: true, 9200: true, 5984: true, 631: true, 4848: true,
}

// HTTPProbe issues a GET / on common web ports and captures the response
// status, Server / X-Powered-By headers, and the <title> from the body. This
// is the structured counterpart to the port scan's banner-grab: where the
// banner is a raw string, this probe emits a typed "http" evidence that the
// HTTPClassifier (and downstream enrichment) can read.
//
// It does NOT follow redirects beyond the first hop (we want the server's own
// identity, not a login portal it redirects to). TLS is attempted on the
// well-known TLS ports; the cert is read by the separate TLSProbe.
//
// Name: "active:http".
type HTTPProbe struct{}

// NewHTTPProbe returns an HTTP probe.
func NewHTTPProbe() *HTTPProbe { return &HTTPProbe{} }

func (p *HTTPProbe) Name() string { return "active:http" }

// Probe GETs ip:port/ for each httpProbePorts that is OPEN (we check the
// port_open evidence in the hint first to avoid dialing closed ports). Since
// the probe framework gives us a single IP and no pre-collected evidence, we
// dial each candidate port directly; closed ports fail fast.
func (p *HTTPProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	timeout := httpProbeTimeout
	if hint.Timeout > 0 && hint.Timeout < timeout {
		timeout = hint.Timeout
	}
	client := &http.Client{
		Timeout: timeout,
		// Allow 1 redirect so a bare "/" → "/app/" still resolves to the real
		// service, but cap there to avoid login-portal churn.
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 1 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	// Trust the cert enough to read headers/title even when self-signed (we're
	// inventorying, not authenticating). The TLSProbe does the deeper cert
	// inspection.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // inventory, not auth
	}
	client.Transport = transport

	var evs []scannerv2.Evidence
	for port := range httpProbePorts {
		select {
		case <-ctx.Done():
			return evs, ctx.Err()
		default:
		}
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		raw := p.fetchOne(ctx, client, scheme, ip, port)
		if raw != nil {
			evs = append(evs, *raw)
		}
	}
	return evs, nil
}

// fetchOne does one GET / and returns an http Evidence on any HTTP response
// (even a 4xx/5xx — the headers/title still identify the server). Returns nil
// when the port isn't speaking HTTP (connection refused, timeout, non-HTTP).
func (p *HTTPProbe) fetchOne(ctx context.Context, client *http.Client, scheme, ip string, port int) *scannerv2.Evidence {
	url := scheme + "://" + ip + ":" + strconv.Itoa(port) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "MiBee-Steward-scanner/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil // not HTTP, or closed, or timed out
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, httpProbeReadLimit))
	bodyStr := string(body)
	raw := map[string]string{
		"status":       resp.Status,
		"server":       resp.Header.Get("Server"),
		"powered_by":   resp.Header.Get("X-Powered-By"),
		"title":        extractHTMLTitle(bodyStr),
		"url":          url,
		"content_type": resp.Header.Get("Content-Type"),
	}
	for k, v := range raw {
		if v == "" {
			delete(raw, k)
		}
	}
	// Only emit if we actually got something useful (status is always set, so
	// require at least one more field to avoid noise from empty responses).
	if len(raw) < 2 {
		return nil
	}
	return &scannerv2.Evidence{
		Source:     "active:http",
		Kind:       "http",
		IP:         ip,
		Port:       port,
		Protocol:   "tcp",
		RawData:    raw,
		Confidence: 0.9,
		ObservedAt: time.Now(),
	}
}

// extractHTMLTitle pulls the <title>...</title> content from an HTML body.
// Case-insensitive tag match; tolerant of attributes on the tag. Returns "" if
// no title is present.
func extractHTMLTitle(body string) string {
	// Find <title ...> case-insensitively.
	lower := strings.ToLower(body)
	startTag := "<title"
	si := strings.Index(lower, startTag)
	if si < 0 {
		return ""
	}
	// Skip past the closing '>' of the opening tag.
	gt := strings.IndexByte(body[si:], '>')
	if gt < 0 {
		return ""
	}
	contentStart := si + gt + 1
	// Find </title>.
	endTag := "</title>"
	ei := strings.Index(lower[contentStart:], endTag)
	if ei < 0 {
		return ""
	}
	title := body[contentStart : contentStart+ei]
	// Collapse whitespace and trim.
	title = strings.TrimSpace(strings.Join(strings.Fields(title), " "))
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}
