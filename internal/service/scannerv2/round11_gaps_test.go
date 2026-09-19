// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package scannerv2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOrchestratorBrandHelpers pins the evidence-fold brand inference: TLS CN
// keywords, HTTP Server fallback, wildcard stripping, and the guards that keep
// generic web-server software from masquerading as the device vendor.
func TestOrchestratorBrandHelpers(t *testing.T) {
	require.Equal(t, "hikvision.com", stripWildcardPrefix("*.hikvision.com"))
	require.Equal(t, "plain.cn", stripWildcardPrefix("plain.cn"))
	require.Equal(t, "*broken", stripWildcardPrefix("*broken"))

	require.Equal(t, "Hikvision", certCNToBrand("web-01.hikvision.com"))
	require.Equal(t, "Dahua", certCNToBrand("DAHUA IPC"))
	require.Equal(t, "Ubiquiti", certCNToBrand("unifi-controller"))
	require.Equal(t, "OpenWrt", certCNToBrand("openwrt.lan"))
	require.Equal(t, "GL.iNet", certCNToBrand("gl-inet-mt3000"))
	require.Equal(t, "", certCNToBrand("www.example.com"))

	// Both cert fields are consulted; issuer org wins when CN is generic.
	require.Equal(t, "iStoreOS", certFieldsToBrand("router.lan", "iStoreOS"))
	require.Equal(t, "Synology", certFieldsToBrand("synology-ds920", ""))

	require.Equal(t, "nginx", httpServerToBrand("nginx/1.24.0"))
	require.Equal(t, "Apache", httpServerToBrand("Apache/2.4"))
	require.Equal(t, "Microsoft IIS", httpServerToBrand("Microsoft-IIS/10"))
	require.Equal(t, "", httpServerToBrand("RandomSoftware/1.0"))

	require.True(t, hasCameraEvidence([]Evidence{{Kind: "rtsp_banner"}, {Kind: "echo"}}))
	require.True(t, hasCameraEvidence([]Evidence{{Kind: "onvif_response"}}))
	require.False(t, hasCameraEvidence([]Evidence{{Kind: "http"}}))

	require.True(t, isWebServerName("NGINX"))
	require.True(t, isWebServerName("Apache"))
	require.False(t, isWebServerName("Hikvision"))
}
