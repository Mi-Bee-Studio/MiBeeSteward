// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. You can use, copy, modify, and
// redistribute it under those terms; see LICENSE for the full text. A
// commercial license is available for use cases the AGPLv3 does not
// accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// exclude_services vetoes a port rule when an excluded classified service
// sits on the keyed port. Field-found shape: a GL.iNet router exposing
// node_exporter on 9100 was typed "printer" by the JetDirect port rule.
func TestMatchDeviceType_Port9100NodeExporterVeto(t *testing.T) {
	// node_exporter classified on 9100 → the printer rule must NOT fire.
	rep := scannerv2.HostReport{
		IP: "192.0.2.10",
		Device: scannerv2.DeviceRef{Fields: map[string]string{
			"node_hostname": "console.gl-inet.com",
		}},
		Services: []scannerv2.ServiceIdentity{
			{Service: "node_exporter", Port: 9100},
			{Service: "http", Port: 80},
			{Service: "https", Port: 443},
			{Service: "ssh", Port: 22},
		},
	}
	typ, src := matchDeviceType(rep)
	require.NotEqual(t, "printer", typ, "node_exporter on 9100 must veto the JetDirect printer rule")
	// The gl-inet hostname keyword (added with the veto) now resolves it.
	require.Equal(t, "router", typ)
	require.Equal(t, "heuristic", src)

	// Same port shape but an UNCLASSIFIED/other service on 9100 → the printer
	// rule still applies (a bannerless real printer is unaffected by the veto).
	rep2 := scannerv2.HostReport{
		IP:       "192.0.2.11",
		Device:   scannerv2.DeviceRef{Fields: map[string]string{}},
		Services: []scannerv2.ServiceIdentity{{Service: "jetdirect", Port: 9100}},
	}
	typ2, _ := matchDeviceType(rep2)
	require.Equal(t, "printer", typ2)
}

// The veto keys on the port the rule named: an excluded service running on a
// DIFFERENT port does not veto.
func TestMatchDeviceType_ExcludeServiceOnOtherPortDoesNotVeto(t *testing.T) {
	rep := scannerv2.HostReport{
		IP:     "192.0.2.12",
		Device: scannerv2.DeviceRef{Fields: map[string]string{}},
		Services: []scannerv2.ServiceIdentity{
			{Service: "node_exporter", Port: 9200}, // different port
			{Service: "unknown", Port: 9100},
		},
	}
	typ, _ := matchDeviceType(rep)
	require.Equal(t, "printer", typ)
}
