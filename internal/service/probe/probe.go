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
	"time"
)

// Result holds the outcome of a single probe execution.
type Result struct {
	Success      bool
	Latency      time.Duration
	ErrorMessage string
	// StatusCode is the final HTTP status code (http module only; 0 otherwise,
	// including error cases where no response was received).
	StatusCode int
	// Phases carries the per-stage timing breakdown (#717): nil when the
	// module does not measure stages (dns) or the run failed before any
	// stage completed. Zero fields inside mean "not measured this run".
	Phases *Phases
}

// Phases is one run's stage decomposition (#717). The whole point is the
// #720 attribution question "is the slowness in resolution, connection, or
// the server" answered per-sample instead of guessed from error text.
type Phases struct {
	ResolvedIP string  `json:"resolved_ip,omitempty"`
	DNSMs      float64 `json:"dns_ms,omitempty"`
	ConnectMs  float64 `json:"connect_ms,omitempty"`
	TLSMs      float64 `json:"tls_ms,omitempty"`
	TTFBMs     float64 `json:"ttfb_ms,omitempty"`
	ReplyTTL   int     `json:"reply_ttl,omitempty"` // icmp: TTL of the echo reply
}

// HasData reports whether any stage was measured.
func (p *Phases) HasData() bool {
	return p != nil && (p.DNSMs > 0 || p.ConnectMs > 0 || p.TLSMs > 0 || p.TTFBMs > 0 || p.ReplyTTL > 0 || p.ResolvedIP != "")
}

// Prober is the interface that all probe types must implement.
type Prober interface {
	Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error)
}
