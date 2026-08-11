// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package routes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
)

// These tests pin the config-resolution helpers that turn a koanf-loaded
// config.ScannerConfig / config.DiscoveryConfig into the concrete values the
// scanner engine consumes. They were previously untested (#171); a refactor of
// the composition root (#157) or the router-ARP path could silently flip a
// fallback (e.g. router_arp.community → snmp_community → "public") without a
// guard here.

func TestRouterCommunity_ResolutionOrder(t *testing.T) {
	// Dedicated router_arp.community wins over everything.
	require.Equal(t, "router-secret", routerCommunity(config.ScannerConfig{
		SNMPCommunity: "global-secret",
		RouterARP:     config.RouterARPConfig{Community: "router-secret"},
	}))
	// No router_arp.community → fall back to the global snmp_community.
	require.Equal(t, "global-secret", routerCommunity(config.ScannerConfig{
		SNMPCommunity: "global-secret",
	}))
	// Neither set → the documented "public" default.
	require.Equal(t, "public", routerCommunity(config.ScannerConfig{}))
}

func TestRouterTimeout_DefaultAndOverride(t *testing.T) {
	// Configured value > 0 is honored.
	require.Equal(t, 9, routerTimeout(config.ScannerConfig{
		RouterARP: config.RouterARPConfig{Timeout: 9},
	}))
	// Zero/unset → the documented 4s default.
	require.Equal(t, 4, routerTimeout(config.ScannerConfig{}))
	require.Equal(t, 4, routerTimeout(config.ScannerConfig{
		RouterARP: config.RouterARPConfig{Timeout: 0},
	}))
}

func TestRouterResidentSourcesOn(t *testing.T) {
	// No resident source enabled → false.
	require.False(t, routerResidentSourcesOn(config.DiscoveryConfig{}))
	// Each source alone flips it true (OR semantics — any one resident reader
	// means the router may see hosts the active sweep missed).
	require.True(t, routerResidentSourcesOn(config.DiscoveryConfig{
		ARPCache: config.DiscoverySourceToggle{Enabled: true},
	}))
	require.True(t, routerResidentSourcesOn(config.DiscoveryConfig{
		DHCPLeases: config.DiscoverySourceToggle{Enabled: true},
	}))
	require.True(t, routerResidentSourcesOn(config.DiscoveryConfig{
		Conntrack: config.DiscoverySourceToggle{Enabled: true},
	}))
}
