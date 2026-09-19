// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package runner

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// Table tests for the pure helpers behind ScanTargets' persistence path —
// they run on every scan report, so their edge behavior is pinned directly.

func TestUniqueOpenPorts(t *testing.T) {
	evs := []scannerv2.Evidence{
		{Kind: "port_open", Port: 443},
		{Kind: "port_open", Port: 80},
		{Kind: "port_open", Port: 443}, // duplicate
		{Kind: "port_open", Port: 0},   // ignored
		{Kind: "echo"},                 // not a port evidence
		{Kind: "snmp", Port: 161},      // not port_open
	}
	require.Equal(t, []int{80, 443}, uniqueOpenPorts(evs))
	require.Empty(t, uniqueOpenPorts(nil))
}

func TestReportJSONFields(t *testing.T) {
	rep := scannerv2.HostReport{
		IP: "10.9.9.9",
		Evidence: []scannerv2.Evidence{
			{Kind: "port_open", Port: 22},
			{Kind: "port_open", Port: 80},
		},
		Services: []scannerv2.ServiceIdentity{
			{Service: "http", Port: 80, Confidence: 0.9},
			{Service: "ssh", Port: 22, Confidence: 1.0},
		},
	}
	ports, services, snmp := reportJSONFields(rep)
	require.JSONEq(t, `[22,80]`, ports)
	require.Contains(t, services, `"http/80"`)
	require.Contains(t, services, `"ssh/22"`)
	require.Equal(t, "{}", snmp, "no SNMP evidence → empty object")

	// Bare report keeps the defaults.
	p2, s2, n2 := reportJSONFields(scannerv2.HostReport{})
	require.Equal(t, "[]", p2)
	require.Equal(t, "{}", s2)
	require.Equal(t, "{}", n2)
}

func TestReportPromFields(t *testing.T) {
	// No fields → all empty.
	_, ne, data := reportPromFields(scannerv2.HostReport{})
	require.Empty(t, ne)
	require.Empty(t, data)

	// Prom URL only.
	rep := scannerv2.HostReport{Device: scannerv2.DeviceRef{Fields: map[string]string{
		"prometheus_url": "http://10.0.0.1:9090/metrics",
	}}}
	prom, ne, data := reportPromFields(rep)
	require.Equal(t, "http://10.0.0.1:9090/metrics", prom)
	require.Empty(t, ne)
	require.Empty(t, data, "no NE URL → no NE data record")

	// NE URL + enriched fields → NE data record carries them.
	rep.Device.Fields["node_exporter_url"] = "http://10.0.0.1:9100/metrics"
	rep.Device.Fields["kernel_version"] = "6.1.0"
	rep.Device.Fields["cpu_count"] = "4"
	prom, ne, data = reportPromFields(rep)
	require.Equal(t, "http://10.0.0.1:9100/metrics", ne)
	require.Contains(t, data, `"metrics_url":"http://10.0.0.1:9100/metrics"`)
	require.Contains(t, data, `"kernel_version":"6.1.0"`)
	require.Contains(t, data, `"cpu_count":"4"`)
	require.NotContains(t, data, "os_type", "unset fields are omitted")
}

func TestBoolToInt(t *testing.T) {
	require.EqualValues(t, 1, boolToInt(true))
	require.EqualValues(t, 0, boolToInt(false))
}
