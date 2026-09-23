// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"encoding/binary"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStubSources_NilConstructors pins the default-build contract of the
// raw-frame stubs: constructors return nil (the sources are absent), and the
// Start/Name methods exist only for the shared call surface.
func TestStubSources_NilConstructors(t *testing.T) {
	require.Nil(t, NewARPScanSource("192.168.0.0/16", time.Second, "", nil, slog.Default()))
	var arp ARPScanSource
	arp.Start(context.Background()) // unreachable in this build; must not panic

	require.Nil(t, NewCDPFrameSource(nil, nil, nil, slog.Default()))
	var cdp CDPFrameSource
	cdp.Start(context.Background())
	require.Equal(t, "cdp_frame", cdp.Name())
}

// TestFileSourceLoops_StartCancel exercises the poll loops' lifecycle: Start
// runs an immediate first sweep and the loop exits on context cancel within
// one interval. Feed each source an explicit (missing) fixture path so the
// sweep is a safe no-op on any host.
func TestFileSourceLoops_StartCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	ct := newConntrackSourceWithPath("192.168.0.0/16", 50*time.Millisecond, "/nonexistent/conntrack", nil, slog.Default())
	ct.Start(ctx)
	require.NotPanics(t, func() { ct.sweep() })

	dhcp := NewDHCPLeasesSource(50*time.Millisecond, "/nonexistent/leases", nil, slog.Default())
	dhcp.Start(ctx)
	require.NotPanics(t, func() { dhcp.sweep() })

	dns := NewDNSLogSource(50*time.Millisecond, "/nonexistent/dnsmasq.log", nil, slog.Default())
	dns.Start(ctx)
	require.NotPanics(t, func() { dns.sweep() })
	require.Contains(t, dns.String(), "dns_log")

	cancel()
	// The loops observe the cancellation within their short interval; give
	// them a moment and confirm the process is healthy (goroutines exited;
	// indirectly verified by no deadlock/panic on a final sweep).
	time.Sleep(120 * time.Millisecond)
	require.NotPanics(t, func() { dns.sweep() })
}

// TestFrameHelpers pins the raw-frame helper math used by the build-tag-gated
// sources, htons byte order and the interface enumeration filters.
func TestFrameHelpers(t *testing.T) {
	require.Equal(t, uint16(0x1234), htons(0x3412), "little-endian host → network order")
	require.Equal(t, binary.BigEndian.Uint16([]byte{0xAB, 0xCD}), htons(0xCDAB))

	ifaces := allUpInterfaces(slog.Default())
	for _, name := range ifaces {
		require.NotEmpty(t, name)
		// loopback never qualifies
		require.NotContains(t, []string{"lo", "loopback0"}, name)
	}

	// Unknown interface → error / false, never panic.
	_, err := ifaceMAC("no-such-iface-xyz")
	require.Error(t, err)
	_, _, ok := ifaceIPv4("no-such-iface-xyz")
	require.False(t, ok)
}
