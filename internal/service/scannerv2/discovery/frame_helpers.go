// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Shared helpers for the raw-frame discovery sources (LLDP, CDP, ARP-scan). All
// three open AF_PACKET raw sockets and need the same small set of utilities:
// htons (AF_PACKET protocols are network-order), interface enumeration, and MAC
// lookup. These used to be duplicated per source under mutually-exclusive build
// tags (lldp_frame_real.go vs cdp_frame_helpers.go); lifting them here lets a new
// raw-socket source (e.g. arp_scan_real.go under WITH_ARPSCAN) compile standalone
// without re-declaring them or depending on another source's build tag.
//
// NOTE: these functions are only referenced from build-tag-gated files
// (lldp_frame_real.go: WITH_LLDP, cdp_frame_real.go: WITH_CDP,
// arp_scan_real.go: WITH_ARPSCAN). In the default build (no tags) they have no
// caller, so golangci-lint would flag them as unused. The nolint:unused
// directives below suppress that — they are NOT dead code, just conditionally
// compiled in.

package discovery

import (
	"encoding/binary"
	"log/slog"
	"net"
	"unsafe"
)

// htons converts a uint16 to network byte order. AF_PACKET takes its protocol
// argument in network order on Linux, so every raw-frame source needs this.
//
//nolint:unused // only called from build-tag-gated raw-frame sources (WITH_LLDP/CDP/ARPSCAN)
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// allUpInterfaces returns the names of all non-loopback, UP interfaces. These
// are the candidates a raw-frame source binds an AF_PACKET socket to.
//
//nolint:unused // only called from build-tag-gated raw-frame sources (WITH_LLDP/CDP/ARPSCAN)
func allUpInterfaces(logger *slog.Logger) []string {
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Warn("frame: enumerate interfaces failed", "error", err)
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

// ifaceMAC returns the hardware address of an interface as a canonical
// "aa:bb:cc:dd:ee:ff" string, or "" when the interface has no hardware address.
//
//nolint:unused // only called from build-tag-gated raw-frame sources (WITH_LLDP/CDP/ARPSCAN)
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

// ifaceIPv4 returns the first IPv4 address (and its /net mask) of an interface,
// used by the ARP-scan source to pick its sender address for ARP requests. The
// second value is false when the interface has no IPv4 address.
//
//nolint:unused // only called from build-tag-gated raw-frame sources (WITH_ARPSCAN)
func ifaceIPv4(name string) (net.IP, *net.IPNet, bool) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, false
	}
	for _, a := range addrs {
		var ip net.IP
		var mask net.IPMask
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
			mask = v.Mask
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, &net.IPNet{IP: ip4, Mask: mask}, true
		}
	}
	return nil, nil, false
}
