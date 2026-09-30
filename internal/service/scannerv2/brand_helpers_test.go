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

// TestLooksLikeBrandJunk pins the mDNS TXT brand guard. AirPlay receivers
// publish txt.md="0,1,2" (capability flags) which previously became the
// device brand verbatim (field-found on a MacBook's AirPlay receiver showing
// brand "0,1,2"). Lettered values — even with digits mixed in — pass.
func TestLooksLikeBrandJunk(t *testing.T) {
	require.True(t, looksLikeBrandJunk("0,1,2"))
	require.True(t, looksLikeBrandJunk("1.0.2"))
	require.True(t, looksLikeBrandJunk("0"))
	require.True(t, looksLikeBrandJunk(""))
	require.False(t, looksLikeBrandJunk("Aqara"))
	require.False(t, looksLikeBrandJunk("MacBookPro17,1"))
	require.False(t, looksLikeBrandJunk("RX-W421"))
}

// TestWebServerBrandDenylistExtension covers the media-server software names
// added after the field session: a NAS fronted by MiniDLNA was branded
// "MiniDLNA", an fnOS NAS "Portable" — both software tokens, not vendors.
func TestWebServerBrandDenylistExtension(t *testing.T) {
	for _, name := range []string{"nginx", "MiniDLNA", "ReadyMedia", "Portable", "Caddy", "lighttpd"} {
		require.True(t, IsWebServerBrand(name), name)
	}
	for _, name := range []string{"Xiaomi", "Viomi", "Synology", "GL.iNet"} {
		require.False(t, IsWebServerBrand(name), name)
	}
}

// TestSSDPBrandSkipsSoftwareNames pins ssdpServerToBrand's denylist: the
// UPnP product token being media-server software must yield "" so the brand
// stays open for OUI/cert/hostname brands.
func TestSSDPBrandSkipsSoftwareNames(t *testing.T) {
	require.Equal(t, "", ssdpServerToBrand("5.15.49-linuxkit-pr DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.3.3"))
	require.Equal(t, "", ssdpServerToBrand("Linux/4.4 UPnP/1.1 nginx/1.24"))
	// A real product token still passes through.
	require.Equal(t, "Sonos", ssdpServerToBrand("Linux UPnP/1.0 Sonos/70.4"))
}
