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
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// The "stp" evidence kind (BRIDGE-MIB dot1dStp walk, #525) folds into a typed
// scan_attributes.stp object: the bridge's own MAC, the network's root bridge
// MAC, whether this bridge IS the root, and the per-port roles.
func TestBuildScanAttributes_STPFold(t *testing.T) {
	rep := scannerv2.HostReport{IP: "10.0.0.2"}
	rep.Evidence = append(rep.Evidence, scannerv2.Evidence{
		Source:   "active:stp_mib",
		Kind:     "stp",
		IP:       "10.0.0.2",
		Protocol: "snmp",
		RawData: map[string]string{
			"bridge_mac":      "aa:bb:cc:dd:ee:02",
			"root_bridge_mac": "aa:bb:cc:dd:ee:02",
			"is_root":         "true",
			"ports":           "port1=designated,port2=root",
		},
	})

	attr := buildScanAttributes(rep)
	require.NotNil(t, attr.STP)
	require.Equal(t, "aa:bb:cc:dd:ee:02", attr.STP.BridgeMAC)
	require.Equal(t, "aa:bb:cc:dd:ee:02", attr.STP.RootBridgeMAC)
	require.True(t, attr.STP.IsRoot)
	require.Equal(t, "port1=designated,port2=root", attr.STP.Ports)
}

// A non-root bridge records the root's MAC but is_root stays false — the
// downstream switch's own view of "who is root" is what orients the graph.
func TestBuildScanAttributes_STPNonRoot(t *testing.T) {
	rep := scannerv2.HostReport{IP: "10.0.0.3"}
	rep.Evidence = append(rep.Evidence, scannerv2.Evidence{
		Source: "active:stp_mib",
		Kind:   "stp",
		RawData: map[string]string{
			"bridge_mac":      "aa:bb:cc:dd:ee:03",
			"root_bridge_mac": "aa:bb:cc:dd:ee:02",
			"is_root":         "false",
			"ports":           "port1=root",
		},
	})

	attr := buildScanAttributes(rep)
	require.NotNil(t, attr.STP)
	require.False(t, attr.STP.IsRoot)
	require.Equal(t, "aa:bb:cc:dd:ee:02", attr.STP.RootBridgeMAC)
}
