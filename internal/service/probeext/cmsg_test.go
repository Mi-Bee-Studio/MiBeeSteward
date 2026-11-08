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

import (
	"encoding/binary"
	"syscall"
	"testing"
	"unsafe"
)

// TestReplyTTLFromCmsg pins the IP_RECVTTL control-message parse: a well
// formed cmsg yields the TTL byte, garbage yields 0.
func TestReplyTTLFromCmsg(t *testing.T) {
	const payload = 53
	data := []byte{payload}
	buf := make([]byte, 64)
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Level = syscall.IPPROTO_IP
	hdr.Type = syscall.IP_TTL
	hdr.SetLen(syscall.CmsgLen(len(data)))
	copy(buf[syscall.CmsgSpace(0):], data)
	if got := replyTTLFromCmsg(buf[:hdr.Len()]); got != payload {
		t.Fatalf("ttl = %d, want %d", got, payload)
	}
	_ = binary.BigEndian
	if got := replyTTLFromCmsg([]byte{1, 2, 3}); got != 0 {
		t.Fatalf("garbage = %d, want 0", got)
	}
	if got := replyTTLFromCmsg(nil); got != 0 {
		t.Fatalf("nil = %d, want 0", got)
	}
}
