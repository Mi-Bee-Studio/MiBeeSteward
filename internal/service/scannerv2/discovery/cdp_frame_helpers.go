// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build WITH_CDP && !WITH_LLDP

// Helper functions for the CDP frame source when the LLDP frame source is not
// also being compiled. These duplicate functions from lldp_frame_real.go to
// avoid a hard dependency on the LLDP build tag.

package discovery

import (
	"encoding/binary"
	"log/slog"
	"net"
	"unsafe"
)

// htons converts a uint16 to network byte order (AF_PACKET protocols are passed
// in network order on Linux).
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// allUpInterfaces returns the names of all non-loopback, UP interfaces.
func allUpInterfaces(logger *slog.Logger) []string {
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Warn("cdp_frame: enumerate interfaces failed", "error", err)
		return nil
	}
	var out []string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, ifi.Name)
	}
	return out
}

// ifaceMAC returns the hardware address of an interface as a canonical string.
func ifaceMAC(name string) (string, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	if ifi.HardwareAddr == nil {
		return "", nil
	}
	return ifi.HardwareAddr.String(), nil
}
