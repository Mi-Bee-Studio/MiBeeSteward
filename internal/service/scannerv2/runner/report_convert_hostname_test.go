// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package runner

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
)

// TestReportedHostToReport_GateWireHostnames pins the agent-wire hostname
// gate: the conversion is where an agent's names first enter the center's
// HostReport pipeline, and devices.name (deviceDisplayName) reads
// node_hostname BEFORE any later backstop — so a mojibake wire hostname
// (broken NBNS/mDNS decoder, passive DNS-sighting name; an agent older than
// the fold-side gates can still send one) must drop here, while clean names
// (CJK marketing suffixes included) pass verbatim.
func TestReportedHostToReport_GateWireHostnames(t *testing.T) {
	garbage := domain.ReportedHost{
		IP: "192.0.2.10", Alive: true, MAC: "aa:bb:cc:dd:ee:10",
		Hostname: "L\x14ÿ.tail1a481.ts.net",
	}
	rep := ReportedHostToReport(garbage)
	require.Empty(t, rep.Device.Fields["node_hostname"], "garbage wire hostname drops")
	require.Empty(t, rep.Device.Name, "Device.Name inherits the gate")

	garbageSNMP := domain.ReportedHost{
		IP: "192.0.2.11", Alive: true, MAC: "aa:bb:cc:dd:ee:11",
		SNMP: &domain.ReportedSNMP{SysName: "bad\x0bname"},
	}
	rep = ReportedHostToReport(garbageSNMP)
	require.Empty(t, rep.Device.Fields["sys_name"], "garbage sysName drops")

	clean := domain.ReportedHost{
		IP: "192.0.2.12", Alive: true, MAC: "aa:bb:cc:dd:ee:12",
		Hostname: "TL-XDR3040易展版",
		SNMP:     &domain.ReportedSNMP{SysName: "sw-core"},
	}
	rep = ReportedHostToReport(clean)
	require.Equal(t, "TL-XDR3040易展版", rep.Device.Fields["node_hostname"])
	require.Equal(t, "TL-XDR3040易展版", rep.Device.Name)
	require.Equal(t, "sw-core", rep.Device.Fields["sys_name"])
}
