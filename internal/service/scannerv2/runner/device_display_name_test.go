// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestDeviceDisplayName covers the name-source priority that fixes the issue-#19
// follow-up: devices.name should carry a real hostname (not the IP) whenever a
// scan collected one, via ANY of the hostname sources. Previously only
// Device.Fields["node_hostname"]/["sys_name"] were consulted, so a scan that
// surfaced a hostname via mDNS/TLS-cert/SNMP evidence (which buildScanAttributes
// merges into scan_attributes.hostname) left devices.name stuck on the IP.
func TestDeviceDisplayName(t *testing.T) {
	ip := "192.168.63.20"

	t.Run("node_hostname field wins", func(t *testing.T) {
		rep := scannerv2.HostReport{IP: ip}
		rep.Device.Fields = map[string]string{"node_hostname": "FROM-FIELD"}
		require.Equal(t, "FROM-FIELD", deviceDisplayName(rep))
	})

	t.Run("sys_name field is second priority", func(t *testing.T) {
		rep := scannerv2.HostReport{IP: ip}
		rep.Device.Fields = map[string]string{"sys_name": "FROM-SYSNAME"}
		require.Equal(t, "FROM-SYSNAME", deviceDisplayName(rep))
	})

	t.Run("merged scan_attributes hostname (mDNS evidence) is third", func(t *testing.T) {
		// The case the fix targets: Fields have NO node_hostname/sys_name (the
		// orchestrator didn't surface them), but an mDNS/hostname evidence row
		// carries the name. buildScanAttributes merges it into .Hostname, and
		// deviceDisplayName must pick it up rather than falling through to IP.
		rep := scannerv2.HostReport{IP: ip}
		rep.Evidence = []scannerv2.Evidence{
			{Kind: "hostname", RawData: map[string]string{"hostname": "MICKEYBEESSD"}},
		}
		require.Equal(t, "MICKEYBEESSD", deviceDisplayName(rep))
	})

	t.Run("SNMP sysName evidence feeds hostname fallback", func(t *testing.T) {
		// A router discovered via SNMP sysObjectID but with no rDNS/mDNS: the
		// sysName is the hostname signal. buildScanAttributes falls back to it
		// (scan_attributes.go:125-126), so deviceDisplayName must too.
		rep := scannerv2.HostReport{IP: ip}
		rep.Evidence = []scannerv2.Evidence{
			{Kind: "snmp", RawData: map[string]string{"sys_name": "NANOPIR4S"}},
		}
		require.Equal(t, "NANOPIR4S", deviceDisplayName(rep))
	})

	t.Run("falls back to IP when no hostname anywhere", func(t *testing.T) {
		rep := scannerv2.HostReport{IP: ip}
		require.Equal(t, ip, deviceDisplayName(rep))
	})
}
