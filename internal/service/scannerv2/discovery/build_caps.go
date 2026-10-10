// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"os"
	"strconv"
	"strings"
)

// Build-tag introspection (#502): doctor and /health report WHICH optional
// frame/ARP capabilities this binary carries, so "the source never fires"
// separates into "not built" vs "built but missing privileges". The lldpBuilt/
// cdpBuilt/arpscanBuilt variables live in tiny tag-gated companions
// (build_lldp_on.go etc.); the default build links the zero values here.

var (
	lldpBuilt    bool
	cdpBuilt     bool
	arpscanBuilt bool
)

// BuiltWithLLDP reports whether the raw-frame LLDPDU listener is compiled in
// (-tags WITH_LLDP); the default build returns false and NewLLDPFrameSource
// returns nil.
func BuiltWithLLDP() bool { return lldpBuilt }

// BuiltWithCDP reports whether the raw-frame CDP listener is compiled in
// (-tags WITH_CDP).
func BuiltWithCDP() bool { return cdpBuilt }

// BuiltWithARPSCAN reports whether the active ARP-sweep source is compiled in
// (-tags WITH_ARPSCAN).
func BuiltWithARPSCAN() bool { return arpscanBuilt }

// EffectiveCapNetRaw reports whether the current process holds CAP_NET_RAW in
// its effective set — the single privilege all three optional sources need
// (AF_PACKET for the frame listeners, raw ARP sockets for the sweep). False
// wherever /proc is absent (non-Linux); callers gate on GOOS separately when
// the distinction matters for reporting.
func EffectiveCapNetRaw() bool {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	caps, ok := parseCapEffHex(string(status))
	return ok && capNetRawPresent(caps)
}

// capNetRawPresent checks bit 13 (CAP_NET_RAW) of a CapEff mask.
func capNetRawPresent(capEff uint64) bool {
	return capEff&(1<<13) != 0
}

// parseCapEffHex extracts the CapEff value from /proc/self/status content.
func parseCapEffHex(status string) (uint64, bool) {
	for _, line := range strings.Split(status, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				return 0, false
			}
			return caps, true
		}
	}
	return 0, false
}
