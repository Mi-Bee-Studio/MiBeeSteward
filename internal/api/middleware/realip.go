// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package middleware

import (
	"net"
	"net/http"
	"strings"
)

// RealIP is a trusted-proxy-aware replacement for chi's deprecated middleware.
// RealIP (which trusts X-Forwarded-For unconditionally — an IP-spoofing risk
// when the service is reachable from untrusted networks). It resolves the
// client IP that downstream middleware/handlers (rate limiting, audit logs,
// RequireAgentToken) see via r.RemoteAddr.
//
// Behavior:
//   - trustedProxies empty (default): the TCP peer address is the client. No
//     header is inspected. This is the safe default — direct exposure without
//     a reverse proxy must not let a client forge its IP via X-Forwarded-For.
//   - trustedProxies populated (CIDRs, e.g. ["127.0.0.1/8", "10.0.0.0/8"]):
//     only when the TCP peer is inside one of these networks is X-Forwarded-For
//     consulted. The LEFTMOST (oldest) entry in the comma-separated list is
//     taken as the real client — this matches the convention that each trusted
//     proxy appends the previous hop, so the first hop is the originating
//     client when all proxies in the chain are trusted. A malformed/non-IP
//     header value falls back to the TCP peer.
//
// Deploy behind nginx/the proxy and set server.trusted_proxies to the proxy's
// source address range (e.g. ["127.0.0.1/32"] for a localhost nginx, or the
// proxy's LAN subnet). Without this knob the service correctly refuses to
// trust the header.
func RealIP(trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Fast path: nothing trusted — pass through untouched, behave exactly
		// like having no RealIP middleware at all (RemoteAddr = TCP peer).
		if len(trustedProxies) == 0 {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ip := trustedClientIP(r, trustedProxies); ip != "" {
				r.RemoteAddr = net.JoinHostPort(ip, portOf(r.RemoteAddr))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// trustedClientIP returns the real client IP when the TCP peer is a trusted
// proxy and X-Forwarded-For is present and well-formed; otherwise "".
func trustedClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	peerIP := hostFromAddr(r.RemoteAddr)
	if peerIP == "" {
		return ""
	}
	if !anyCIDRContains(trustedProxies, peerIP) {
		return "" // untrusted source — do not honor the header
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return ""
	}
	// X-Forwarded-For: client, proxy1, proxy2 — the leftmost is the original.
	parts := strings.Split(xff, ",")
	first := strings.TrimSpace(parts[0])
	if first == "" {
		return ""
	}
	// Strip any zone/port; validate it's a usable IP. A malformed value means
	// we cannot trust the header — fall back to the TCP peer (return "").
	if ip := net.ParseIP(first); ip != nil {
		return ip.String()
	}
	return ""
}

// anyCIDRContains reports whether ip falls in any of the CIDRs.
func anyCIDRContains(cidrs []*net.IPNet, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, c := range cidrs {
		if c.Contains(parsed) {
			return true
		}
	}
	return false
}

// hostFromAddr extracts the host part from a host:port RemoteAddr (or returns
// the input as-is if there's no port, e.g. an already-stripped value).
func hostFromAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// portOf extracts the port from a host:port RemoteAddr (returns "80" if the
// value isn't host:port — covers the rare case of a pre-stripped RemoteAddr,
// where the port is unknown and downstream code only inspects the host).
func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return "80"
}

// ParseCIDRs parses a list of CIDR strings (e.g. ["127.0.0.1/8", "10.0.0.0/8"])
// into net.IPNet values. A bare IP (no /prefix) is treated as a /32 (v4) or
// /128 (v6) for convenience. Invalid entries are skipped — callers should
// validate at config-load time, so this is a defensive best-effort.
func ParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Accept bare IPs as single-host CIDRs.
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					c += "/32"
				} else {
					c += "/128"
				}
			} else {
				continue
			}
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		out = append(out, ipnet)
	}
	return out
}
