// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"net"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
)

// localIPMACPairs enumerates the host's own interface bindings: every IPv4
// address held by an UP, non-loopback interface with a hardware MAC. This is
// ground truth the OS hands us for free — and precisely the fact ARP
// self-scan can never learn: a frame addressed to the local host takes the
// kernel's loopback shortcut, so no wire frame ever teaches the scanner its
// own MAC (#522).
func localIPMACPairs() []scannerv2.IPMACPair {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var pairs []scannerv2.IPMACPair
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		mac := store.NormalizeMAC(ifi.HardwareAddr.String())
		if mac == "" {
			continue // tunnels and other MAC-less virtual links
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				pairs = append(pairs, scannerv2.IPMACPair{IP: v4.String(), MAC: mac})
			}
		}
	}
	return pairs
}

// AnchorLocalInterfaces fills the center's own interface MACs into its device
// rows (#522). Without the anchor, every MAC-keyed neighbor source (LLDP/CDP
// frame listeners, hostapd edges) resolves its local end against a MAC-less
// row and silently drops the adjacency. Runs once at wiring time (routes.go)
// and as a per-scan finalize step — self-healing, so a row created by any
// scan is anchored by that same scan.
func (rn *Runner) AnchorLocalInterfaces(ctx context.Context) {
	rn.anchorLocalInterfaces(ctx, rn.networkID)
}

// anchorLocalInterfaces is the per-run form: scheduled scans pass the TASK's
// network (a multi-network center anchors its own MACs into the rows of the
// network it just scanned, not the wiring-time singleton network).
func (rn *Runner) anchorLocalInterfaces(ctx context.Context, networkID sql.NullInt64) {
	if rn.repo == nil {
		return
	}
	pairs := localIPMACPairs()
	if len(pairs) == 0 {
		return
	}
	anchored, err := rn.repo.AnchorLocalInterfaces(ctx, networkID, pairs)
	if err != nil {
		rn.logger.Debug("local anchor: store call failed", "error", err)
		return
	}
	if anchored > 0 {
		rn.logger.Info("local anchor: filled center interface MACs into device rows",
			"anchored", anchored)
	}
}
