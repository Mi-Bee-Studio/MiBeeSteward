// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package domain

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Synthetic probing (拨测) request/response types. A probe target is an
// EXPLICIT user-configured endpoint (typically external/internet) probed on a
// fixed interval, the blackbox_exporter model (module × target), unlike the
// discovery-driven scanner or the device-bound heartbeat.

// ValidProbeModules is the whitelist of probe modules. Mirrors the
// probe_targets.module CHECK constraint.
var ValidProbeModules = map[string]bool{
	"http": true,
	"tls":  true,
	"tcp":  true,
	"icmp": true,
	"dns":  true,
}

// Probe target bounds. Mirrored by the probe_targets CHECK constraints; kept
// here too so the API rejects invalid values before touching the DB (a CHECK
// violation would show up as an opaque 500).
const (
	ProbeIntervalMinSeconds = 10
	ProbeIntervalMaxSeconds = 86400
	ProbeTimeoutMinSeconds  = 1
	ProbeTimeoutMaxSeconds  = 60
)

// Probe vantage values (#277). The vantage is the EXECUTION plan for a target:
// where its probes run. It is not part of target identity, one
// target row, one name, results split per vantage.
const (
	// ProbeVantageCenter: the center itself executes (default, current behavior).
	ProbeVantageCenter = "center"
	// ProbeVantageAll: center + every registered agent each run a track.
	ProbeVantageAll = "all"
	// ProbeVantageAgentPrefix: a specific agent executes ("agent:{agent_id}").
	ProbeVantageAgentPrefix = "agent:"
)

// NormalizeProbeVantage validates and canonicalizes a vantage value. Empty
// (the common case / older clients) resolves to "center". Accepts "center",
// "all", or "agent:{non-empty id}".
func NormalizeProbeVantage(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return ProbeVantageCenter, nil
	}
	if v == ProbeVantageCenter || v == ProbeVantageAll {
		return v, nil
	}
	if strings.HasPrefix(v, ProbeVantageAgentPrefix) {
		id := strings.TrimPrefix(v, ProbeVantageAgentPrefix)
		if id == "" || len(id) > 100 {
			return "", fmt.Errorf("vantage agent id must be 1-100 characters")
		}
		return v, nil
	}
	return "", fmt.Errorf("vantage must be \"center\", \"all\", or \"agent:{agent_id}\"")
}

// ProbeOptions carries per-module execution semantics (#605), stored as JSON
// in probe_targets.options and shipped verbatim to vantage agents (the wire
// Spec mirrors this shape). One shared struct across modules keeps the DB
// column, the API and the agent codec in a 1:1 mapping; fields only ever
// apply to their own module and ValidateProbeOptions rejects fields foreign
// to the module so a typo cannot silently no-op.
//
// Deliberately NOT a secrets store: no credentials, tokens, or auth headers
// ever belong here - options land in the command channel, which must stay
// secret-free by design.
type ProbeOptions struct {
	// http module.
	Method          string `json:"method,omitempty"`            // GET (default) | HEAD
	ExpectedStatus  []int  `json:"expected_status,omitempty"`   // exact allowed codes; empty = status < 400 (legacy semantics)
	Keyword         string `json:"keyword,omitempty"`           // body match after the status check
	KeywordMode     string `json:"keyword_mode,omitempty"`      // contains (default) | not_contains | regex
	IgnoreTLSErrors bool   `json:"ignore_tls_errors,omitempty"` // default false = verify TLS like the center always has

	// dns module.
	Record      string   `json:"record,omitempty"`       // A (default) | AAAA | CNAME | TXT
	Resolver    string   `json:"resolver,omitempty"`     // host[:port]; empty = the host's system resolver
	ExpectedIPs []string `json:"expected_ips,omitempty"` // A/AAAA answers must intersect this set

	// tcp module.
	Send       string `json:"send,omitempty"`        // optional payload written right after connect (ASCII; no binary in v1)
	Expect     string `json:"expect,omitempty"`      // banner match against the first bytes read
	ExpectMode string `json:"expect_mode,omitempty"` // contains (default) | regex
}

// Probe option enums.
const (
	// ProbeKeywordContains / ProbeKeywordNotContains / ProbeKeywordRegex are
	// the shared match modes for http keyword and tcp expect.
	ProbeKeywordContains    = "contains"
	ProbeKeywordNotContains = "not_contains"
	ProbeKeywordRegex       = "regex"

	// ProbeRecordA/AAAA/CNAME/TXT are the dns module record types.
	ProbeRecordA     = "A"
	ProbeRecordAAAA  = "AAAA"
	ProbeRecordCNAME = "CNAME"
	ProbeRecordTXT   = "TXT"

	// ProbeSourceManual/Auto/System are the probe_targets.source values.
	ProbeSourceManual = "manual"
	ProbeSourceAuto   = "auto"
	ProbeSourceSystem = "system"
)

// ValidateProbeOptions checks one module's option block: enum values, list
// bounds, and per-module field gating (fields that do not apply to the module
// are rejected instead of silently ignored). A nil options pointer or an
// empty struct is always valid (the pre-#605 shape).
func ValidateProbeOptions(module string, opts *ProbeOptions) error {
	if opts == nil {
		return nil
	}
	setFor := func(fields ...bool) bool {
		for _, s := range fields {
			if s {
				return true
			}
		}
		return false
	}

	httpSet := setFor(opts.Method != "", len(opts.ExpectedStatus) > 0, opts.Keyword != "",
		opts.KeywordMode != "", opts.IgnoreTLSErrors)
	dnsSet := setFor(opts.Record != "", opts.Resolver != "", len(opts.ExpectedIPs) > 0)
	tcpSet := setFor(opts.Send != "", opts.Expect != "", opts.ExpectMode != "")

	switch module {
	case "http":
		if dnsSet || tcpSet {
			return fmt.Errorf("options contain dns/tcp fields that do not apply to the http module")
		}
	case "dns":
		if httpSet || tcpSet {
			return fmt.Errorf("options contain http/tcp fields that do not apply to the dns module")
		}
	case "tcp":
		if httpSet || dnsSet {
			return fmt.Errorf("options contain http/dns fields that do not apply to the tcp module")
		}
	case "icmp", "tls":
		if httpSet || dnsSet || tcpSet {
			return fmt.Errorf("the %s module takes no options", module)
		}
		return nil
	default:
		return fmt.Errorf("module must be one of http, tls, tcp, icmp, dns")
	}

	// Shared match-mode enum (http keyword_mode / tcp expect_mode).
	matchMode := func(field, mode string) error {
		switch mode {
		case "", ProbeKeywordContains, ProbeKeywordNotContains, ProbeKeywordRegex:
			return nil
		default:
			return fmt.Errorf("%s must be contains, not_contains, or regex", field)
		}
	}

	switch module {
	case "http":
		switch opts.Method {
		case "", "GET", "HEAD":
		default:
			return fmt.Errorf("method must be GET or HEAD")
		}
		if len(opts.ExpectedStatus) > 16 {
			return fmt.Errorf("expected_status must hold at most 16 codes")
		}
		for _, c := range opts.ExpectedStatus {
			if c < 100 || c > 599 {
				return fmt.Errorf("expected_status codes must be 100-599")
			}
		}
		if len(opts.Keyword) > 256 {
			return fmt.Errorf("keyword must be at most 256 characters")
		}
		if opts.Keyword == "" && opts.KeywordMode != "" {
			return fmt.Errorf("keyword_mode requires keyword")
		}
		if err := matchMode("keyword_mode", opts.KeywordMode); err != nil {
			return err
		}
	case "dns":
		switch opts.Record {
		case "", ProbeRecordA, ProbeRecordAAAA, ProbeRecordCNAME, ProbeRecordTXT:
		default:
			return fmt.Errorf("record must be one of A, AAAA, CNAME, TXT")
		}
		if opts.Resolver != "" {
			if strings.Contains(opts.Resolver, "/") || strings.TrimSpace(opts.Resolver) == "" {
				return fmt.Errorf("resolver must be a host or host:port")
			}
			// Bare host without a port is fine (53 implied).
			var portStr string
			if _, p, serr := net.SplitHostPort(opts.Resolver); serr == nil {
				portStr = p
			}
			if portStr != "" {
				port, cerr := strconv.Atoi(portStr)
				if cerr != nil || port < 1 || port > 65535 {
					return fmt.Errorf("resolver port must be 1-65535")
				}
			}
		}
		if len(opts.ExpectedIPs) > 8 {
			return fmt.Errorf("expected_ips must hold at most 8 addresses")
		}
		for _, ip := range opts.ExpectedIPs {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("expected_ips entries must be valid IP addresses")
			}
		}
		if len(opts.ExpectedIPs) > 0 && opts.Record != "" && opts.Record != ProbeRecordA && opts.Record != ProbeRecordAAAA {
			return fmt.Errorf("expected_ips applies to record A or AAAA only")
		}
	case "tcp":
		if len(opts.Send) > 256 {
			return fmt.Errorf("send must be at most 256 characters")
		}
		if len(opts.Expect) > 256 {
			return fmt.Errorf("expect must be at most 256 characters")
		}
		if opts.Expect == "" && opts.ExpectMode != "" {
			return fmt.Errorf("expect_mode requires expect")
		}
		if err := matchMode("expect_mode", opts.ExpectMode); err != nil {
			return err
		}
	}
	return nil
}

// ProbeTargetRequest is the create payload for POST /api/v1/probe-targets.
type ProbeTargetRequest struct {
	Name            string        `json:"name"`
	Module          string        `json:"module"`
	Target          string        `json:"target"`
	IntervalSeconds int           `json:"interval_seconds"`
	TimeoutSeconds  int           `json:"timeout_seconds"`
	Enabled         *bool         `json:"enabled,omitempty"`
	Notes           string        `json:"notes"`
	Vantage         string        `json:"vantage"`
	Options         *ProbeOptions `json:"options,omitempty"`
	// DeviceID optionally binds the target to a discovered asset (#606).
	// Existence is checked by the service (the domain layer has no DB).
	DeviceID *int64 `json:"device_id,omitempty"`
}

// UpdateProbeTargetRequest is the partial-update payload for PUT. Nil fields
// keep their current value (mirrors UpdateScanTaskRequest); a non-nil
// DeviceID of 0 explicitly clears the binding.
type UpdateProbeTargetRequest struct {
	Name            *string       `json:"name,omitempty"`
	Module          *string       `json:"module,omitempty"`
	Target          *string       `json:"target,omitempty"`
	IntervalSeconds *int          `json:"interval_seconds,omitempty"`
	TimeoutSeconds  *int          `json:"timeout_seconds,omitempty"`
	Enabled         *bool         `json:"enabled,omitempty"`
	Notes           *string       `json:"notes,omitempty"`
	Vantage         *string       `json:"vantage,omitempty"`
	Options         *ProbeOptions `json:"options,omitempty"`
	DeviceID        *int64        `json:"device_id,omitempty"`
}

// ProbeTargetResponse is a probe target as served by the API. last_* fields
// denormalize the newest outcome (empty/0 = never probed); they reflect the
// CENTER track only. vantage_latest carries each executor's newest row
// (agent tracks included), which is the multi-vantage display source.
type ProbeTargetResponse struct {
	ID              int64                `json:"id"`
	Name            string               `json:"name"`
	Module          string               `json:"module"`
	Target          string               `json:"target"`
	IntervalSeconds int                  `json:"interval_seconds"`
	TimeoutSeconds  int                  `json:"timeout_seconds"`
	Enabled         bool                 `json:"enabled"`
	Notes           string               `json:"notes"`
	LastRunAt       string               `json:"last_run_at,omitempty"`
	LastStatus      string               `json:"last_status,omitempty"`
	LastLatencyMs   float64              `json:"last_latency_ms"`
	LastError       string               `json:"last_error,omitempty"`
	CreatedAt       string               `json:"created_at"`
	UpdatedAt       string               `json:"updated_at"`
	Vantage         string               `json:"vantage"`
	VantageLatest   []ProbeVantageLatest `json:"vantage_latest,omitempty"`
	Options         *ProbeOptions        `json:"options,omitempty"`
	// DeviceID is 0 for free (unbound) targets; omitted from JSON in that case.
	DeviceID int64  `json:"device_id,omitempty"`
	Source   string `json:"source"` // manual | auto | system (#606)
}

// ProbeVantageLatest is the newest result of one vantage's track, used by the
// list UI to show every executor's outcome side by side.
type ProbeVantageLatest struct {
	Vantage      string  `json:"vantage"`
	Status       string  `json:"status"`
	LatencyMs    float64 `json:"latency_ms"`
	ErrorMessage string  `json:"error_message,omitempty"`
	CheckedAt    string  `json:"checked_at"`
}

type ProbeTargetListResponse struct {
	Targets []ProbeTargetResponse `json:"targets"`
	Total   int                   `json:"total"`
}

// ProbeResultResponse is one history row of a target's probe series.
type ProbeResultResponse struct {
	ID           int64   `json:"id"`
	TargetID     int64   `json:"target_id"`
	Status       string  `json:"status"`
	LatencyMs    float64 `json:"latency_ms"`
	StatusCode   int     `json:"status_code"`
	ErrorMessage string  `json:"error_message,omitempty"`
	TLSVersion   string  `json:"tls_version,omitempty"`
	CertNotAfter string  `json:"cert_not_after,omitempty"`
	CertTrusted  *bool   `json:"cert_trusted,omitempty"` // nil = no cert collected this run
	CheckedAt    string  `json:"checked_at"`
	Vantage      string  `json:"vantage"` // which executor produced this row (#277)
}

type ProbeResultListResponse struct {
	Results []ProbeResultResponse `json:"results"`
	Total   int                   `json:"total"`
}

// ValidateProbeTargetRequest validates a create request. The per-module target
// grammar is the contract the executor relies on:
//   - http: absolute http/https URL (host may be a DNS name, external probing
//     is the whole point, so no RFC1918 filtering)
//   - tls: host:port (port required; e.g. "github.com:443", "mail.example.com:993")
//   - tcp: host:port
//   - icmp: bare host or IP (ICMP has no port)
func ValidateProbeTargetRequest(req ProbeTargetRequest) error {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > 100 {
		return fmt.Errorf("name must be at most 100 characters")
	}
	if !ValidProbeModules[req.Module] {
		return fmt.Errorf("module must be one of http, tls, tcp, icmp, dns")
	}
	if strings.TrimSpace(req.Target) == "" {
		return fmt.Errorf("target is required")
	}
	if req.IntervalSeconds == 0 {
		req.IntervalSeconds = 60
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 10
	}
	if req.IntervalSeconds < ProbeIntervalMinSeconds || req.IntervalSeconds > ProbeIntervalMaxSeconds {
		return fmt.Errorf("interval_seconds must be between %d and %d", ProbeIntervalMinSeconds, ProbeIntervalMaxSeconds)
	}
	if req.TimeoutSeconds < ProbeTimeoutMinSeconds || req.TimeoutSeconds > ProbeTimeoutMaxSeconds {
		return fmt.Errorf("timeout_seconds must be between %d and %d", ProbeTimeoutMinSeconds, ProbeTimeoutMaxSeconds)
	}
	if req.TimeoutSeconds >= req.IntervalSeconds {
		return fmt.Errorf("timeout_seconds must be smaller than interval_seconds")
	}
	if len(req.Notes) > 500 {
		return fmt.Errorf("notes must be at most 500 characters")
	}
	if _, err := NormalizeProbeVantage(req.Vantage); err != nil {
		return err
	}
	if err := ValidateProbeOptions(req.Module, req.Options); err != nil {
		return err
	}
	return ValidateProbeTargetGrammar(req.Module, strings.TrimSpace(req.Target))
}

// ValidateProbeTargetGrammar checks the target string against the module's
// expected shape. Shared by create and update validation.
func ValidateProbeTargetGrammar(module, target string) error {
	switch module {
	case "http":
		u, err := url.Parse(target)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("target must be an absolute URL (e.g. https://example.com/healthz)")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("target scheme must be http or https")
		}
		if u.Port() != "" {
			if _, err := strconv.Atoi(u.Port()); err != nil {
				return fmt.Errorf("target port is not numeric")
			}
		}
		return nil
	case "tls", "tcp":
		host, portStr, err := net.SplitHostPort(target)
		if err != nil || host == "" || portStr == "" {
			return fmt.Errorf("target must be host:port (e.g. example.com:443)")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("target port must be 1-65535")
		}
		return nil
	case "icmp", "dns":
		// icmp: bare host or IP (ICMP has no port). dns: bare domain - the
		// resolver is an option, not part of the target.
		if strings.Contains(target, "/") || strings.Contains(target, ":") {
			return fmt.Errorf("target must be a bare host or IP (no port, no path)")
		}
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("target is required")
		}
		return nil
	default:
		return fmt.Errorf("module must be one of http, tls, tcp, icmp, dns")
	}
}
