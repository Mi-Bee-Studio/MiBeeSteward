// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//go:build windows

package discovery

import (
	"net"
	"syscall"
)

// mdnsJoinControl is the Windows counterpart (see mdns_control_unix.go for
// the full rationale). Windows has no IP_ADD_MEMBERSHIP via the generic
// RawConn syscall surface here and product deployments are Linux-only, so
// this variant sets SO_REUSEADDR only — best-effort announcement on dev
// boxes, the group join (and thus query delivery) is expected to be absent.
func mdnsJoinControl(group string) func(network, address string, c syscall.RawConn) error {
	_ = net.ParseIP(group)
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			// syscall.SO_REUSEADDR is not defined on windows in the stdlib
			// syscall package for RawConn control; WSA_FLAG_OVERLAPPED
			// sockets created by Go already allow address reuse semantics
			// via SO_REUSEADDR where available — absence degrades to a plain
			// bind, which is the honest behavior.
			const soReuseAddr = 4 // SO_REUSEADDR on Windows
			_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soReuseAddr, 1)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
