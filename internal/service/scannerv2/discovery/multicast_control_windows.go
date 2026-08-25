// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build windows

package discovery

import (
	"fmt"
	"syscall"
)

// reuseJoinControl is the Windows counterpart of the Unix socket-control
// implementation (multicast_control_unix.go). Joining an IPv4 multicast group
// needs IP_ADD_MEMBERSHIP on a syscall.Handle-typed descriptor; instead of
// carrying a Windows socket path this project cannot exercise in CI, Windows
// builds decline the join: ListenPacket fails with this error and
// MulticastSource.run skips the mDNS/SSDP listeners with a warning. The
// multicast source is supplemental — every other discovery source and the
// whole engine keep working, and `go build`/`go test ./...` stay green on
// Windows dev machines, which is the point of the split (#321). Deployments
// are Linux; the CI windows-build job keeps this file honest.
func reuseJoinControl(_, _ string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return fmt.Errorf("multicast group join (IP_ADD_MEMBERSHIP) not implemented on windows builds")
	}
}
