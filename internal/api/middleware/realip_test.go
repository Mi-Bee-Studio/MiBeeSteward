// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package middleware_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/middleware"
)

// capturedRemoteAddr lets the inner handler record what the RealIP middleware
// set r.RemoteAddr to — that's what downstream code (rate limiters, audit
// logs) actually consumes.
func realipTestHandler(captured *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*captured = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	}
}

func doRequest(t *testing.T, h http.Handler, remoteAddr, xff string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "handler did not return 200")
}

// When trusted_proxies is empty, the TCP peer is the client regardless of any
// X-Forwarded-For header — a client cannot forge its IP. This is the safe
// default for direct exposure.
func TestRealIP_EmptyTrustedProxies_IgnoresHeader(t *testing.T) {
	var got string
	h := middleware.RealIP(nil)(realipTestHandler(&got))
	// Client tries to forge 1.2.3.4 via the header.
	doRequest(t, h, "203.0.113.9:1000", "1.2.3.4")
	require.Equal(t, "203.0.113.9:1000", got, "empty trusted_proxies must ignore X-Forwarded-For")
}

// When the TCP peer is a trusted proxy, the leftmost X-Forwarded-For entry is
// taken as the real client IP (the proxy appends; the first hop originates).
func TestRealIP_TrustedProxy_HonorsHeader(t *testing.T) {
	trusted := middleware.ParseCIDRs([]string{"127.0.0.1/8"})
	var got string
	h := middleware.RealIP(trusted)(realipTestHandler(&got))
	// nginx on localhost forwards for a real client at 198.51.100.5.
	doRequest(t, h, "127.0.0.1:40000", "198.51.100.5")
	require.Equal(t, "198.51.100.5:40000", got, "trusted proxy: client IP should come from X-Forwarded-For")
}

// A multi-hop chain: client → proxy1 → proxy2(localhost). Leftmost entry wins.
func TestRealIP_MultiHopChain_LeftmostWins(t *testing.T) {
	trusted := middleware.ParseCIDRs([]string{"127.0.0.1/8"})
	var got string
	h := middleware.RealIP(trusted)(realipTestHandler(&got))
	doRequest(t, h, "127.0.0.1:40000", "198.51.100.5, 10.0.0.1, 10.0.0.2")
	require.Equal(t, "198.51.100.5:40000", got, "multi-hop: leftmost (original client) should win")
}

// Untrusted source — even with the header, the TCP peer is the client. This
// is the spoofing defense: a random internet host claiming to be behind a
// proxy must not be able to forge its IP.
func TestRealIP_UntrustedSource_IgnoresHeader(t *testing.T) {
	trusted := middleware.ParseCIDRs([]string{"127.0.0.1/8"})
	var got string
	h := middleware.RealIP(trusted)(realipTestHandler(&got))
	// An external host (not in 127.0.0.1/8) claims to forward for 1.2.3.4.
	doRequest(t, h, "203.0.113.99:5000", "1.2.3.4")
	require.Equal(t, "203.0.113.99:5000", got, "untrusted source must not be able to forge X-Forwarded-For")
}

// Trusted proxy but no header — fall back to the TCP peer (the proxy itself).
func TestRealIP_TrustedProxy_NoHeader(t *testing.T) {
	trusted := middleware.ParseCIDRs([]string{"10.0.0.0/8"})
	var got string
	h := middleware.RealIP(trusted)(realipTestHandler(&got))
	doRequest(t, h, "10.0.0.1:40000", "")
	require.Equal(t, "10.0.0.1:40000", got, "no header: must keep TCP peer unchanged")
}

// A malformed X-Forwarded-For from a trusted proxy must NOT break the request
// or poison the IP — it falls back to the TCP peer.
func TestRealIP_MalformedHeader_FallsBackToPeer(t *testing.T) {
	trusted := middleware.ParseCIDRs([]string{"127.0.0.1/8"})
	var got string
	h := middleware.RealIP(trusted)(realipTestHandler(&got))
	doRequest(t, h, "127.0.0.1:40000", "not-an-ip")
	require.Equal(t, "127.0.0.1:40000", got, "malformed header must fall back to TCP peer")
}

// ParseCIDRs accepts bare IPs (treats them as /32) and skips invalid entries.
func TestParseCIDRs_BareIPAndInvalid(t *testing.T) {
	cidrs := middleware.ParseCIDRs([]string{"127.0.0.1", "10.0.0.0/8", "garbage", ""})
	require.Len(t, cidrs, 2, "bare IP + valid CIDR; empty + garbage skipped")
	require.True(t, cidrs[0].Contains(net.ParseIP("127.0.0.1")))
	require.True(t, cidrs[1].Contains(net.ParseIP("10.5.5.5")))
	require.False(t, cidrs[1].Contains(net.ParseIP("11.0.0.1")))
}

// IPv6 trusted proxy.
func TestRealIP_IPv6_TrustedProxy(t *testing.T) {
	trusted := middleware.ParseCIDRs([]string{"::1/128"})
	var got string
	h := middleware.RealIP(trusted)(realipTestHandler(&got))
	doRequest(t, h, "[::1]:40000", "2001:db8::1")
	require.Equal(t, "[2001:db8::1]:40000", got, "IPv6 proxy should honor IPv6 X-Forwarded-For")
}
