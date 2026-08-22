// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package cidrutil

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseNetwork(t *testing.T) {
	t.Run("standard CIDR", func(t *testing.T) {
		n, err := ParseNetwork("192.168.63.0/24")
		require.NoError(t, err)
		require.NotNil(t, n)
		require.True(t, n.Contains(net.ParseIP("192.168.63.5")))
		require.False(t, n.Contains(net.ParseIP("192.168.62.5")))
	})
	t.Run("bare IPv4 is /32", func(t *testing.T) {
		n, err := ParseNetwork("192.168.63.1")
		require.NoError(t, err)
		require.True(t, n.Contains(net.ParseIP("192.168.63.1")))
		require.False(t, n.Contains(net.ParseIP("192.168.63.2")))
	})
	t.Run("whitespace trimmed", func(t *testing.T) {
		n, err := ParseNetwork("  10.0.0.0/8  ")
		require.NoError(t, err)
		require.True(t, n.Contains(net.ParseIP("10.1.2.3")))
	})
	t.Run("empty -> ErrEmptyCIDR", func(t *testing.T) {
		n, err := ParseNetwork("")
		require.ErrorIs(t, err, ErrEmptyCIDR)
		require.Nil(t, n)
	})
	t.Run("whitespace-only -> ErrEmptyCIDR", func(t *testing.T) {
		n, err := ParseNetwork("   ")
		require.ErrorIs(t, err, ErrEmptyCIDR)
		require.Nil(t, n)
	})
	t.Run("invalid cidr errors (not ErrEmptyCIDR)", func(t *testing.T) {
		_, err := ParseNetwork("not-a-network")
		require.Error(t, err)
		require.False(t, errors.Is(err, ErrEmptyCIDR))
	})
	t.Run("invalid prefix errors", func(t *testing.T) {
		_, err := ParseNetwork("192.168.63.0/33")
		require.Error(t, err)
	})
}

func TestContainsIP(t *testing.T) {
	n, err := ParseNetwork("192.168.63.0/24")
	require.NoError(t, err)
	require.True(t, ContainsIP(n, "192.168.63.1"))
	require.True(t, ContainsIP(n, "192.168.63.254"))
	require.False(t, ContainsIP(n, "192.168.62.1"))
	require.False(t, ContainsIP(n, "10.0.0.1"))
	t.Run("nil network is false, no panic", func(t *testing.T) {
		require.False(t, ContainsIP(nil, "192.168.63.1"))
	})
	t.Run("garbage ip is false, no panic", func(t *testing.T) {
		require.False(t, ContainsIP(n, "garbage"))
	})
	t.Run("empty ip is false, no panic", func(t *testing.T) {
		require.False(t, ContainsIP(n, ""))
	})
}

func TestPartitionTargets(t *testing.T) {
	n, err := ParseNetwork("192.168.62.0/24")
	require.NoError(t, err)
	t.Run("all in", func(t *testing.T) {
		in, out, err := PartitionTargets("192.168.62.1,192.168.62.100", n)
		require.NoError(t, err)
		require.ElementsMatch(t, []string{"192.168.62.1", "192.168.62.100"}, in)
		require.Empty(t, out)
	})
	t.Run("mixed in/out", func(t *testing.T) {
		// The exact real-world bug from issue #19: agent-62's network is /62,
		// but a command told it to scan 63.0/24 — every host lands "out".
		// 254 = 256 minus the reserved .0 network / .255 broadcast addresses
		// (excluded from CIDR enumeration since #254).
		in, out, err := PartitionTargets("192.168.63.0/24", n)
		require.NoError(t, err)
		require.Empty(t, in)
		require.Len(t, out, 254)
		require.Contains(t, out, "192.168.63.1")
		require.Contains(t, out, "192.168.63.20")
		require.Contains(t, out, "192.168.63.254")
		require.NotContains(t, out, "192.168.63.0")
		require.NotContains(t, out, "192.168.63.255")
	})
	t.Run("cross-subnet mix", func(t *testing.T) {
		in, out, err := PartitionTargets("192.168.62.5,192.168.63.5,10.0.0.1", n)
		require.NoError(t, err)
		require.Equal(t, []string{"192.168.62.5"}, in)
		require.ElementsMatch(t, []string{"192.168.63.5", "10.0.0.1"}, out)
	})
	t.Run("range spanning boundary", func(t *testing.T) {
		in, out, err := PartitionTargets("192.168.61.250-192.168.62.5", n)
		require.NoError(t, err)
		// .250, .251, .252, .253, .254, .255 on the 61 side are OUT;
		// .0-.5 on the 62 side are IN.
		require.Len(t, out, 6)
		require.Len(t, in, 6)
		require.Contains(t, in, "192.168.62.1")
		require.Contains(t, out, "192.168.61.255")
	})
	t.Run("nil network -> empty, no error", func(t *testing.T) {
		in, out, err := PartitionTargets("192.168.62.1", nil)
		require.NoError(t, err)
		require.Nil(t, in)
		require.Nil(t, out)
	})
	t.Run("empty targets errors", func(t *testing.T) {
		_, _, err := PartitionTargets("", n)
		require.Error(t, err)
	})
	t.Run("garbage targets errors", func(t *testing.T) {
		_, _, err := PartitionTargets("not-an-ip", n)
		require.Error(t, err)
	})
}

// TestValidateTargets_Reserved covers the entry-point validation added for
// issue #317: reserved/non-routable address space must be rejected no matter
// which syntax names it, while ordinary private space passes.
func TestValidateTargets_Reserved(t *testing.T) {
	rejects := []string{
		// The exact benchmark incident: a /22 of loopback produced 1022
		// phantom devices on the test center.
		"127.8.0.0/22",
		"127.0.0.1",
		"127.0.0.0/8",
		"0.0.0.0/0",
		"0.0.0.0",
		"169.254.0.0/16",
		"169.254.1.5",
		"224.0.0.0/4",
		"239.255.255.250",
		"255.255.255.255",
		"240.0.0.0/4",
		"250.1.2.3",
		// Block that merely overlaps reserved space: 126.0.0.0/7 ends at
		// 127.255.255.255 (loopback).
		"126.0.0.0/7",
		// Ranges and comma-separated lists name reserved space too.
		"127.0.0.1-127.0.0.5",
		"192.168.63.0/24,127.0.0.1",
		"192.168.63.1-5,0.0.0.0",
		// IPv6 reserved space.
		"::1",
		"fe80::/10",
	}
	for _, tc := range rejects {
		t.Run(tc, func(t *testing.T) {
			err := ValidateTargets(tc)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrReservedTarget)
		})
	}
	accepts := []string{
		"192.168.63.0/24",
		"10.0.0.0/8",
		"172.16.5.9",
		"192.168.63.1-254",
		"192.168.63.1,192.168.62.7",
		"100.64.0.0/10", // CGNAT: not a reserved class, routable-ish
	}
	for _, tc := range accepts {
		t.Run("ok: "+tc, func(t *testing.T) {
			require.NoError(t, ValidateTargets(tc))
		})
	}
}

// TestExpandTargets_HostAddressesOnly pins the #254 fix: CIDR expansion drops
// the network and directed-broadcast addresses for IPv4 prefixes up to /30.
func TestExpandTargets_HostAddressesOnly(t *testing.T) {
	t.Run("/24 drops .0 and .255", func(t *testing.T) {
		ips, err := ExpandTargets("192.168.63.0/24")
		require.NoError(t, err)
		require.Len(t, ips, 254)
		require.Equal(t, "192.168.63.1", ips[0])
		require.Equal(t, "192.168.63.254", ips[len(ips)-1])
	})
	t.Run("/31 keeps both (RFC 3021 point-to-point)", func(t *testing.T) {
		ips, err := ExpandTargets("192.168.63.0/31")
		require.NoError(t, err)
		require.Equal(t, []string{"192.168.63.0", "192.168.63.1"}, ips)
	})
	t.Run("/32 is a single host", func(t *testing.T) {
		ips, err := ExpandTargets("192.168.63.5/32")
		require.NoError(t, err)
		require.Equal(t, []string{"192.168.63.5"}, ips)
	})
	t.Run("/30 keeps the two host addresses", func(t *testing.T) {
		ips, err := ExpandTargets("192.168.1.0/30")
		require.NoError(t, err)
		require.Equal(t, []string{"192.168.1.1", "192.168.1.2"}, ips)
	})
	t.Run("range keeps its explicit endpoints", func(t *testing.T) {
		ips, err := ExpandTargets("192.168.63.0-3")
		require.NoError(t, err)
		require.Len(t, ips, 4) // explicit range: caller named those addresses
	})
	t.Run("reserved spec rejected", func(t *testing.T) {
		_, err := ExpandTargets("127.8.0.0/22")
		require.ErrorIs(t, err, ErrReservedTarget)
	})
}

// TestValidateTargetsFor_EscapeHatch pins the scanner.allow_reserved_targets
// semantics: reserved ranges pass, syntax errors still fail.
func TestValidateTargetsFor_EscapeHatch(t *testing.T) {
	require.NoError(t, ValidateTargetsFor("127.8.0.0/22", true))
	require.NoError(t, ValidateTargetsFor("0.0.0.0/0,127.0.0.1", true))
	require.ErrorIs(t, ValidateTargetsFor("127.8.0.0/22,garbage", true), ErrInvalidTarget)
	_, err := ExpandTargetsFor("127.8.0.0/22", true)
	require.NoError(t, err)
	require.ErrorIs(t, ValidateTargetsFor("127.8.0.0/22", false), ErrReservedTarget)
}
