// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEdgeSemantics verifies the protocol→(edge_type, confidence) mapping that
// drives topology_edges classification. L2 protocols (switch-sourced) must map
// to "l2" with high confidence; ARP (same-subset reachability) must map to "l3"
// with lower confidence.
func TestEdgeSemantics(t *testing.T) {
	cases := []struct {
		protocol string
		wantType string
		minConf  float64 // confidence must be >= this
	}{
		{"LLDP", "l2", 0.8},
		{"CDP", "l2", 0.75},
		{"Bridge-MIB", "l2", 0.75},
		{"Q-BRIDGE-MIB", "l2", 0.75},
		{"ARP", "l3", 0.0},
	}
	for _, c := range cases {
		t.Run(c.protocol, func(t *testing.T) {
			et, conf := edgeSemantics(c.protocol)
			require.Equal(t, c.wantType, et)
			require.GreaterOrEqual(t, conf, c.minConf)
		})
	}
	// ARP must be strictly lower confidence than LLDP (l3 is weaker evidence).
	_, lldpConf := edgeSemantics("LLDP")
	_, arpConf := edgeSemantics("ARP")
	require.Greater(t, lldpConf, arpConf)
}

// TestEdgeMetadata confirms the port-context JSON is well-formed and omits
// empty fields. The protocol field is always included when non-empty.
func TestEdgeMetadata(t *testing.T) {
	require.Equal(t, "{}", edgeMetadata("", "", ""))
	require.JSONEq(t, `{"protocol":"LLDP"}`, edgeMetadata("", "", "LLDP"))
	require.JSONEq(t, `{"local_port":"Gi0/1","remote_port":"Gi1/2","protocol":"LLDP"}`,
		edgeMetadata("Gi0/1", "Gi1/2", "LLDP"))
	require.JSONEq(t, `{"local_port":"Gi0/1","protocol":"Bridge-MIB"}`,
		edgeMetadata("Gi0/1", "", "Bridge-MIB"))
}
