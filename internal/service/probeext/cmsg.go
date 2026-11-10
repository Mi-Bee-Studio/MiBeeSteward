//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probeext

import "syscall"

// replyTTLFromCmsg extracts the IP_TTL control message (IP_RECVTTL) from a
// recvmsg ancillary buffer. Pure and platform-independent so its parsing
// stays testable everywhere (#719).
func replyTTLFromCmsg(oob []byte) int {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_TTL && len(m.Data) >= 1 {
			return int(m.Data[0])
		}
	}
	return 0
}
