// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package netinfo

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	cases := map[string]string{
		// real NICs / soft-router LAN
		"eth0":    KindLan,
		"enp3s0":  KindLan,
		"en0":     KindLan,
		"br-lan":  KindLan,
		"usb0":    KindLan,
		"unknown": KindLan, // fallback: unknown is likelier a real NIC
		// wireless
		"wlan0":     KindWireless,
		"wlp2s0":    KindWireless,
		"wlx001122": KindWireless,
		// container / virtualization
		"docker0":         KindVirtual,
		"vetha1b2c3":      KindVirtual,
		"br-abc123def456": KindVirtual,
		"flannel.1":       KindVirtual,
		"cali123ab":       KindVirtual,
		"cni0":            KindVirtual,
		"virbr0":          KindVirtual,
		// overlay / vpn
		"wg0":          KindVPN,
		"tailscale0":   KindVPN,
		"zerotier-abc": KindVPN,
		"tun0":         KindVPN,
		"tap0":         KindVPN,
	}
	for name, want := range cases {
		require.Equal(t, want, classify(name), "classify(%q)", name)
	}
}

func TestSuggestCIDRClampsTo24(t *testing.T) {
	// /16 DHCP lease → the /24 containing the host's own address.
	require.Equal(t, "192.168.63.0/24", suggestCIDR(net.ParseIP("192.168.63.41").To4(), 16))
	// /20 → /24 as well.
	require.Equal(t, "10.1.2.0/24", suggestCIDR(net.ParseIP("10.1.2.3").To4(), 20))
	// /24 stays /24 (normalized network address).
	require.Equal(t, "192.168.1.0/24", suggestCIDR(net.ParseIP("192.168.1.77").To4(), 24))
	// Longer prefixes stay as configured.
	require.Equal(t, "10.0.0.128/25", suggestCIDR(net.ParseIP("10.0.0.200").To4(), 25))
	require.Equal(t, "10.0.0.4/30", suggestCIDR(net.ParseIP("10.0.0.6").To4(), 30))
}

func TestSnapshotShape(t *testing.T) {
	rep := Snapshot()

	seenPrimary := 0
	cidrs := map[string]bool{}
	for _, iface := range rep.Interfaces {
		require.NotEmpty(t, iface.Name)
		require.NotNil(t, net.ParseIP(iface.IPv4), "ipv4 must parse: %s", iface.IPv4)
		require.NotContains(t, iface.IPv4, "169.254.", "link-local must be skipped")
		require.NotEqual(t, "127.0.0.1", iface.IPv4)
		require.Positive(t, iface.Addresses)
		_, suggested, err := net.ParseCIDR(iface.SuggestedCIDR)
		require.NoError(t, err, "suggested cidr must parse: %s", iface.SuggestedCIDR)
		suggLen, _ := suggested.Mask.Size()
		require.GreaterOrEqual(t, suggLen, 24, "suggestion is never wider than /24: %s", iface.SuggestedCIDR)
		require.Contains(t, []string{KindLan, KindWireless, KindVirtual, KindVPN}, iface.Kind)
		if iface.Primary {
			seenPrimary++
		}
		cidrs[iface.CIDR] = true
	}
	// On any host with a default route there is exactly one primary; a
	// route-less CI box legitimately has none. Never two.
	require.LessOrEqual(t, seenPrimary, 1)

	// Sorted: primary first, then lan < wireless < vpn < virtual.
	rank := func(i int) int { return kindRank(rep.Interfaces[i].Kind) }
	for i := 1; i < len(rep.Interfaces); i++ {
		a, b := rep.Interfaces[i-1], rep.Interfaces[i]
		if !a.Primary && b.Primary {
			t.Fatalf("primary must sort first: %v before %v", a, b)
		}
		if a.Primary == b.Primary && rank(i-1) > rank(i) {
			t.Fatalf("kind order violated: %s(kind=%s) before %s(kind=%s)", a.Name, a.Kind, b.Name, b.Kind)
		}
	}
}

func TestWarningFor(t *testing.T) {
	docker := Interface{Name: "eth0", IPv4: "172.17.0.2", Kind: KindLan, Primary: true}

	// Happy host: a LAN candidate exists, no warning.
	require.Equal(t, "", warningFor(Report{Interfaces: []Interface{{Name: "eth0", IPv4: "192.168.1.10", Kind: KindLan, Primary: true}}}))

	// Container with a 172.16/12 primary = bridge mode.
	require.Equal(t, WarnBridgeContainer, warningFor(Report{
		Container:  true,
		Interfaces: []Interface{docker},
	}))

	// Container on host networking (LAN IP) = fine.
	hostNet := docker
	hostNet.IPv4 = "192.168.1.10"
	require.Equal(t, "", warningFor(Report{Container: true, Interfaces: []Interface{hostNet}}))

	// 10/8 must NOT be treated as a bridge signal (real LANs live there).
	ten := docker
	ten.IPv4 = "10.10.0.5"
	require.Equal(t, "", warningFor(Report{Container: true, Interfaces: []Interface{ten}}))

	// Nothing LAN-like at all.
	require.Equal(t, WarnNoLAN, warningFor(Report{Interfaces: []Interface{{Name: "wg0", IPv4: "10.99.1.2", Kind: KindVPN, Primary: true}}}))
	require.Equal(t, WarnNoLAN, warningFor(Report{}))
}
