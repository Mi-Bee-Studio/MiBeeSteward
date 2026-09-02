// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIcmpPingGroupRangeCheck pins the #288 operator diagnostic: the GL.iNet
// OpenWrt firmware ships ping_group_range="1 0" (lo>hi = disabled), which
// makes every unprivileged ICMP probe fail with "permission denied" even for
// root. The check's decision table must classify all four shapes the field
// can produce, and stay silent on unparseable input (never a false failure).
func TestIcmpPingGroupRangeCheck(t *testing.T) {
	t.Run("disabled range means probes will fail", func(t *testing.T) {
		c, ok := icmpPingGroupRangeCheck("1 0\n", 0)
		require.True(t, ok)
		require.Equal(t, "fail", c.status)
		require.Contains(t, c.detail, "disabled")
	})

	t.Run("gid inside range is ok", func(t *testing.T) {
		c, ok := icmpPingGroupRangeCheck("0 2147483647\n", 0)
		require.True(t, ok)
		require.Equal(t, "ok", c.status)
		c, ok = icmpPingGroupRangeCheck("100 200\n", 150)
		require.True(t, ok)
		require.Equal(t, "ok", c.status)
	})

	t.Run("gid outside range warns", func(t *testing.T) {
		c, ok := icmpPingGroupRangeCheck("100 200\n", 0)
		require.True(t, ok)
		require.Equal(t, "warn", c.status)
		require.Contains(t, c.detail, "outside")
	})

	t.Run("unparseable input emits no check", func(t *testing.T) {
		_, ok := icmpPingGroupRangeCheck("garbage", 0)
		require.False(t, ok)
		_, ok = icmpPingGroupRangeCheck("", 0)
		require.False(t, ok)
		_, ok = icmpPingGroupRangeCheck("5", 0) // one number, not two
		require.False(t, ok)
	})
}

func TestHumanBytes(t *testing.T) {
	require.Equal(t, "512 B", humanBytes(512))
	require.Equal(t, "1.0 KB", humanBytes(1<<10))
	require.Equal(t, "5.0 MB", humanBytes(5<<20))
	require.Equal(t, "2.0 GB", humanBytes(2<<30))
}
