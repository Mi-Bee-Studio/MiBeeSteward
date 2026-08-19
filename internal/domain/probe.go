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
// fixed interval — the blackbox_exporter model (module × target), unlike the
// discovery-driven scanner or the device-bound heartbeat.

// ValidProbeModules is the whitelist of probe modules. Mirrors the
// probe_targets.module CHECK constraint.
var ValidProbeModules = map[string]bool{
	"http": true,
	"tls":  true,
	"tcp":  true,
	"icmp": true,
}

// Probe target bounds. Mirrored by the probe_targets CHECK constraints; kept
// here too so the API rejects invalid values before touching the DB (a CHECK
// violation would surface as an opaque 500).
const (
	ProbeIntervalMinSeconds = 10
	ProbeIntervalMaxSeconds = 86400
	ProbeTimeoutMinSeconds  = 1
	ProbeTimeoutMaxSeconds  = 60
)

// ProbeTargetRequest is the create payload for POST /api/v1/probe-targets.
type ProbeTargetRequest struct {
	Name            string `json:"name"`
	Module          string `json:"module"`
	Target          string `json:"target"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	Enabled         *bool  `json:"enabled,omitempty"`
	Notes           string `json:"notes"`
}

// UpdateProbeTargetRequest is the partial-update payload for PUT. Nil fields
// keep their current value (mirrors UpdateScanTaskRequest).
type UpdateProbeTargetRequest struct {
	Name            *string `json:"name,omitempty"`
	Module          *string `json:"module,omitempty"`
	Target          *string `json:"target,omitempty"`
	IntervalSeconds *int    `json:"interval_seconds,omitempty"`
	TimeoutSeconds  *int    `json:"timeout_seconds,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
	Notes           *string `json:"notes,omitempty"`
}

// ProbeTargetResponse is a probe target as served by the API. last_* fields
// denormalize the newest outcome (empty/0 = never probed).
type ProbeTargetResponse struct {
	ID              int64   `json:"id"`
	Name            string  `json:"name"`
	Module          string  `json:"module"`
	Target          string  `json:"target"`
	IntervalSeconds int     `json:"interval_seconds"`
	TimeoutSeconds  int     `json:"timeout_seconds"`
	Enabled         bool    `json:"enabled"`
	Notes           string  `json:"notes"`
	LastRunAt       string  `json:"last_run_at,omitempty"`
	LastStatus      string  `json:"last_status,omitempty"`
	LastLatencyMs   float64 `json:"last_latency_ms"`
	LastError       string  `json:"last_error,omitempty"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
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
}

type ProbeResultListResponse struct {
	Results []ProbeResultResponse `json:"results"`
	Total   int                   `json:"total"`
}

// ValidateProbeTargetRequest validates a create request. The per-module target
// grammar is the contract the executor relies on:
//   - http: absolute http/https URL (host may be a DNS name — external probing
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
		return fmt.Errorf("module must be one of http, tls, tcp, icmp")
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
	case "icmp":
		if strings.Contains(target, "/") || strings.Contains(target, ":") {
			return fmt.Errorf("target must be a bare host or IP (no port, no path)")
		}
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("target is required")
		}
		return nil
	default:
		return fmt.Errorf("module must be one of http, tls, tcp, icmp")
	}
}
