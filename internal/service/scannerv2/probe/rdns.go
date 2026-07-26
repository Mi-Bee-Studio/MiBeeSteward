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
	"net"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// RDNSConfig tunes the reverse-DNS probe. It mirrors config.RDNSConfig but
// lives in the probe package so the probe can be constructed without importing
// config (avoids a cycle: engine → probe, engine → config).
type RDNSConfig struct {
	// DNSServers overrides the system resolver. Each entry is "host" or
	// "host:port" (port defaults to 53). Empty → use net.DefaultResolver.
	DNSServers []string
	// Timeout is the per-lookup deadline. <=0 → 2s.
	Timeout time.Duration
}

// RDNSProbe resolves the target IP's hostname via reverse DNS (PTR lookup).
// This is the cheapest source of a human-readable hostname: many networks
// (especially with mDNS reflectors or DNS servers that synthesize PTR records
// from DHCP leases) will answer for nearly every live host.
//
// When cfg.DNSServers is populated the probe uses a dedicated resolver pointed
// at those servers (typical use: the LAN's DNS that holds DHCP-PTR records the
// center's /etc/resolv.conf can't reach). Otherwise it falls back to the system
// resolver. Issue #20.
//
// Name: "active:rdns".
type RDNSProbe struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewRDNSProbe returns a reverse-DNS probe using the default system resolver
// (backwards-compatible: callers that don't pass a config get the old behavior).
func NewRDNSProbe() *RDNSProbe { return NewRDNSProbeWithConfig(RDNSConfig{}) }

// NewRDNSProbeWithConfig returns a reverse-DNS probe. When cfg.DNSServers is
// non-empty a dedicated resolver is built that dials ONLY those servers,
// bypassing /etc/resolv.conf — this is how a center box reaches a LAN DNS it
// wouldn't otherwise query. Empty → system resolver.
func NewRDNSProbeWithConfig(cfg RDNSConfig) *RDNSProbe {
	p := &RDNSProbe{resolver: net.DefaultResolver, timeout: cfg.Timeout}
	if len(cfg.DNSServers) == 0 {
		return p
	}
	// Normalize to "host:port" entries the dialer expects.
	servers := make([]string, 0, len(cfg.DNSServers))
	for _, s := range cfg.DNSServers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return p
	}
	p.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Round-robin isn't worth it for a 1-2 server list; dial the first
			// reachable one. DNS lookups are short and infrequent (one per host
			// per scan), so simplicity beats a full balancer here.
			var lastErr error
			for _, srv := range servers {
				d := net.Dialer{}
				c, err := d.DialContext(ctx, "udp", srv)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		},
	}
	return p
}

func (p *RDNSProbe) Name() string { return "active:rdns" }

// Probe issues a PTR lookup for ip. Returns one "hostname" Evidence on success,
// nil evidence on miss/timeout (a host with no PTR record is normal).
func (p *RDNSProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	timeout := p.timeout
	if hint.Timeout > 0 && (timeout <= 0 || hint.Timeout < timeout) {
		timeout = hint.Timeout
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	names, err := p.resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return nil, nil
	}
	// net.LookupAddr returns FQDNs with a trailing dot ("host.example."); strip
	// the trailing dot for cleaner display and downstream matching.
	host := strings.TrimSuffix(names[0], ".")
	if host == "" {
		return nil, nil
	}
	return []scannerv2.Evidence{{
		Source:     "active:rdns",
		Kind:       "hostname",
		IP:         ip,
		RawData:    map[string]string{"hostname": host},
		Confidence: 0.8, // rDNS is best-effort; DHCP/mDNS names can be stale
		ObservedAt: time.Now(),
	}}, nil
}
