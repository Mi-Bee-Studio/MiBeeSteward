// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build !windows

package discovery

import (
	"net"
	"syscall"
)

// reuseJoinControl is a ListenConfig.Control that sets SO_REUSEADDR AND joins
// the multicast group via IP_ADD_MEMBERSHIP. SO_REUSEADDR lets the listener bind
// alongside a system resolver (avahi, systemd-resolved) that already holds
// :5353 / :1900; it deliberately does NOT set SO_REUSEPORT (that would split
// incoming datagrams between us and the resolver, halving both our coverage).
//
// The IP_ADD_MEMBERSHIP is the critical part that was missing before: binding to
// a multicast address (or to 0.0.0.0:port) does NOT by itself cause the kernel
// to deliver multicast packets to the socket. The kernel only forwards packets
// sent to a group to sockets that have explicitly joined that group. Without the
// join, the listener opens successfully and the read loop runs forever — but
// receives nothing, because the kernel never hands it any multicast traffic.
// This was the root cause of the multicast source emitting zero events despite
// devices broadcasting on the link.
//
// ifaceName selects the interface to join on (empty = the first up,
// multicast-capable, non-loopback interface, which is the common single-NIC
// case). Joining on a specific interface is required for IP_ADD_MEMBERSHIP to
// receive link-local multicast (224.0.0.251) — the kernel needs to know which
// L2 segment to listen on.
//
// Unix-only (see multicast_control_windows.go): the socket-descriptor
// arguments of syscall.SetsockoptInt/SetsockoptIPMreq take an int here but a
// syscall.Handle (uintptr) on Windows, so this file carries the `!windows`
// build constraint the tagless multicast.go used to lack (#321).
func reuseJoinControl(group, ifaceName string) func(network, address string, c syscall.RawConn) error {
	ifi, ifiErr := multicastInterface(ifaceName)
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if sockErr != nil {
				return
			}
			if ifiErr != nil {
				sockErr = ifiErr
				return
			}
			mreq := syscall.IPMreq{}
			copy(mreq.Multiaddr[:], net.ParseIP(group).To4())
			// Bind membership to the interface's IPv4 address (INADDR_ANY +
			// imr_interface = kernel picks the default-route iface, but pinning
			// it makes the choice deterministic and works when there is no
			// default route, e.g. on a host with only a link-local config).
			if ifi != nil && len(ifi.Addr) >= 4 {
				copy(mreq.Interface[:], ifi.Addr[:4])
			}
			sockErr = syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP,
				syscall.IP_ADD_MEMBERSHIP, &mreq)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
