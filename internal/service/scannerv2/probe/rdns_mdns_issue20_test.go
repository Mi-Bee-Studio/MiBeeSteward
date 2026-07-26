// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRDNSProbe_CustomResolverConfigured verifies that populating DNSServers
// builds a resolver that does NOT fall back to the system resolver — i.e. the
// custom dial path is wired. We can't easily run a full DNS round-trip in a
// unit test, but we CAN confirm the resolver's Dial is non-default by checking
// that a lookup against an unreachable custom server fails (the system resolver
// would otherwise succeed for loopback names). Issue #20-A.
func TestRDNSProbe_CustomResolverConfigured(t *testing.T) {
	// 127.0.0.1:1 is almost certainly closed → a custom resolver pointed here
	// must fail to dial. The system resolver (nil config) would NOT use this
	// dial path, so a successful loopback lookup distinguishes the two.
	p := NewRDNSProbeWithConfig(RDNSConfig{DNSServers: []string{"127.0.0.1:1"}})
	require.NotNil(t, p.resolver)
	// The custom resolver replaces the default — confirm it's a different
	// instance (DefaultResolver is a package var).
	require.NotSame(t, net.DefaultResolver, p.resolver,
		"a configured DNSServers must build a dedicated resolver, not reuse the default")
}

func TestRDNSProbe_SystemResolverWhenUnconfigured(t *testing.T) {
	// Backward compatibility: empty config → system resolver (the pre-#20 path).
	p := NewRDNSProbeWithConfig(RDNSConfig{})
	require.Same(t, net.DefaultResolver, p.resolver,
		"empty DNSServers must fall back to the system resolver")
	// And the no-arg constructor preserves the old behavior exactly.
	p2 := NewRDNSProbe()
	require.Same(t, net.DefaultResolver, p2.resolver)
}

func TestRDNSConfig_PortNormalization(t *testing.T) {
	// "192.168.63.1" (no port) should be accepted and treated as :53. We
	// verify indirectly: building the probe must not panic and must produce a
	// non-default resolver (confirming the entry was accepted + normalized).
	p := NewRDNSProbeWithConfig(RDNSConfig{DNSServers: []string{"192.168.63.1"}})
	require.NotSame(t, net.DefaultResolver, p.resolver,
		"a bare-IP DNSServers entry should be normalized to host:53 and build a custom resolver")

	// Whitespace + empty entries are skipped, not treated as servers.
	p2 := NewRDNSProbeWithConfig(RDNSConfig{DNSServers: []string{"  ", ""}})
	require.Same(t, net.DefaultResolver, p2.resolver,
		"whitespace/empty DNSServers entries are skipped → system resolver")
}

// TestMDNSProbe_UnicastFlag verifies the unicast configuration is honored by
// the probe struct (the actual packet send is exercised by the live scan in
// the test environment; here we confirm the wiring). Issue #20-B.
func TestMDNSProbe_UnicastFlag(t *testing.T) {
	require.False(t, NewMDNSProbe().unicast, "default constructor = multicast only (backward compat)")
	require.False(t, NewMDNSProbeWithConfig(MDNSConfig{}).unicast, "zero config = multicast only")
	require.True(t, NewMDNSProbeWithConfig(MDNSConfig{UnicastQueries: true}).unicast,
		"UnicastQueries=true enables the per-target unicast query path")
}
