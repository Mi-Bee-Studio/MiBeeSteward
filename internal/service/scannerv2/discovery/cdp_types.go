// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Shared types for the CDP frame source, used by both the stub (default) and
// real (WITH_CDP) builds. No build tag — always compiled.

package discovery

// cdpEdge is one neighbor adjacency extracted from a captured CDP frame. The
// fields mirror scannerv2.NeighborSpec but stay local to this package to avoid
// an import cycle (discovery → scannerv2 would cycle). The real listener
// (cdp_frame_real.go, WITH_CDP) builds these; the caller's neighborSink
// consumes them.
type cdpEdge struct {
	NeighborMAC     string // canonical aa:bb:cc:dd:ee:ff (from Ethernet src MAC)
	Protocol        string // always "CDP"
	LocalMAC        string // the surveyed interface's MAC (the listener host)
	LocalPort       string // the interface name the CDP frame was received on
	RemotePort      string // from the Port ID TLV
	DeviceID        string // from the Device ID TLV
	Platform        string // from the Platform TLV
	SoftwareVersion string // from the Software Version TLV
	NeighborIP      string // from the Addresses TLV (first IPv4 if present)
}
