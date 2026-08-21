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

	"mibee-steward/internal/service/scannerv2/engine"

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
		// but a command told it to scan 63.0/24 — every one of those lands "out".
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

// TestExpandTargets_ParityWithEngine guards against drift between this
// package's expandTargets and the engine's ParseScanTargets. If someone changes
// the engine's target syntax, this test forces them to update cidrutil too (or
// refactor to a shared helper) rather than silently diverging.
func TestExpandTargets_ParityWithEngine(t *testing.T) {
	cases := []string{
		"192.168.63.0/30",
		"192.168.63.1",
		"192.168.63.1-192.168.63.5",
		"192.168.63.1-5",
		"192.168.63.1,192.168.63.2,10.0.0.1",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			ours, err := expandTargets(tc)
			require.NoError(t, err)
			theirs, err := engine.ParseScanTargets(tc)
			require.NoError(t, err)
			require.Equal(t, theirs, ours, "cidrutil.expandTargets diverged from engine.ParseScanTargets")
		})
	}
}
