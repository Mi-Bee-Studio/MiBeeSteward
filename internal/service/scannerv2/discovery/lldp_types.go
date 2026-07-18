// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Shared types for the LLDP frame source, used by both the stub (default) and
// real (WITH_LLDP) builds. No build tag — always compiled.

package discovery

// lldpEdge is one neighbor adjacency extracted from a captured LLDPDU. The
// fields mirror scannerv2.NeighborSpec but stay local to this package to avoid
// an import cycle (discovery → scannerv2 would cycle). The real listener
// (lldp_frame_real.go, WITH_LLDP) builds these; the caller's neighborSink
// consumes them.
type lldpEdge struct {
	NeighborMAC string // canonical aa:bb:cc:dd:ee:ff (subtype-4 chassis id, or the Ethernet src MAC)
	Protocol    string // always "LLDP"
	LocalMAC    string // the surveyed interface's MAC (the listener host)
	LocalPort   string // the interface name the LLDPDU was received on
	RemotePort  string // from the Port ID TLV
}
