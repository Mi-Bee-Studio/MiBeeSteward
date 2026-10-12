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

	"mibee-steward/internal/service/scannerv2"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
)

// The wire protocol carries the interface census (#529) and route table
// (#528) as flat arrays on ReportedHost (the evidence slice never crosses
// the wire). ReportedHostToReport must rebuild them as "interface"/"route"
// evidence so ApplyReport's extractors land them in device_interfaces and
// the route-table topology edges - exactly like a local scan.
func TestReportedHostToReport_InterfacesAndRoutes(t *testing.T) {
	h := domain.ReportedHost{
		IP:    "10.0.0.1",
		Alive: true,
		MAC:   "aa:bb:cc:dd:ee:01",
		Interfaces: []domain.ReportedInterface{
			{IfIndex: 1, IfName: "eth0", IfDescr: "Ethernet0", MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.1", SpeedMbps: 1000},
			{IfIndex: 2, IfName: "eth1"},
		},
		Routes: []domain.ReportedRoute{
			{DestCIDR: "172.16.0.0/12", NextHop: "10.0.0.254", IfIndex: 2, Proto: "ospf"},
		},
	}
	rep := ReportedHostToReport(h)

	faces := scannerv2.ExtractInterfaces(rep.Evidence)
	require.Len(t, faces, 2, "both census rows must survive the wire hop")
	require.Equal(t, 1, faces[0].IfIndex)
	require.Equal(t, "eth0", faces[0].IfName)
	require.Equal(t, "10.0.0.1", faces[0].IP)
	require.EqualValues(t, 1000, faces[0].Speed)

	routes := scannerv2.ExtractRoutes(rep.Evidence)
	require.Len(t, routes, 1)
	require.Equal(t, "172.16.0.0/12", routes[0].DestCIDR)
	require.Equal(t, "ospf", routes[0].Proto)
}
