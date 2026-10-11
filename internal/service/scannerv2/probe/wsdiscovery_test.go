// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"net"
	"testing"
)

// A realistic ONVIF ProbeMatches envelope: namespace prefixes as emitted by
// a common camera stack (gSOAP/ONVIF), Scopes as a quoted-URI list carrying
// the ONVIF name/hardware/location URIs, XAddrs pointing at the device
// service, EndpointReference with the device UUID.
const wsdSampleEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>
    <a:RelatesTo>urn:uuid:mibee-steward-probe</a:RelatesTo>
  </s:Header>
  <s:Body>
    <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
      <d:ProbeMatch>
        <a:EndpointReference><a:Address>urn:uuid:1e2d3c4b-5a69-7788-99aa-bbccddeeff00</a:Address></a:EndpointReference>
        <d:Types>tds:NetworkVideoTransmitter</d:Types>
        <d:Scopes value="onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/IPC-122 onvif://www.onvif.org/location/courtyard"/>
        <d:XAddrs>http://192.0.2.42:8080/onvif/device_service</d:XAddrs>
        <d:MetadataVersion>1</d:MetadataVersion>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>`

func TestParseWSDiscoveryMatch(t *testing.T) {
	raw := parseWSDiscoveryMatch([]byte(wsdSampleEnvelope))
	if raw == nil {
		t.Fatal("envelope with a ProbeMatch must parse")
	}
	if raw["types"] != "tds:NetworkVideoTransmitter" {
		t.Errorf("types = %q", raw["types"])
	}
	if raw["xaddrs"] != "http://192.0.2.42:8080/onvif/device_service" {
		t.Errorf("xaddrs = %q", raw["xaddrs"])
	}
	if raw["address"] != "urn:uuid:1e2d3c4b-5a69-7788-99aa-bbccddeeff00" {
		t.Errorf("address = %q", raw["address"])
	}
	// ONVIF scope unpacking, incl. the %20 decode.
	if raw["name"] != "Front Door" {
		t.Errorf("name = %q, want Front Door (percent-decoded)", raw["name"])
	}
	if raw["hardware"] != "IPC-122" {
		t.Errorf("hardware = %q", raw["hardware"])
	}
	if raw["service_hint"] != "onvif" {
		t.Errorf("service_hint = %q", raw["service_hint"])
	}
}

func TestParseWSDiscoveryMatchIgnoresOtherMessages(t *testing.T) {
	hello := `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` +
		`<d:Hello xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><d:Types>tds:NetworkVideoTransmitter</d:Types></d:Hello>` +
		`</s:Body></s:Envelope>`
	if raw := parseWSDiscoveryMatch([]byte(hello)); raw != nil {
		t.Fatalf("Hello (unsolicited) must be ignored, got %+v", raw)
	}
	if raw := parseWSDiscoveryMatch([]byte("not xml at all")); raw != nil {
		t.Fatalf("garbage must yield nil, got %+v", raw)
	}
	if raw := parseWSDiscoveryMatch(nil); raw != nil {
		t.Fatalf("nil packet must yield nil")
	}
}

func TestWSDEvidenceStrictSourceFilter(t *testing.T) {
	// One ProbeMatch from the target, one from another camera on the segment
	// (cross-talk), plus a garbage packet from the target: only the first
	// becomes evidence — the strict source-IP filter is what keeps a /24
	// scan from smearing identities (#507 acceptance criterion).
	packets := []udpPacket{
		{src: net.ParseIP("192.0.2.42"), data: []byte(wsdSampleEnvelope)},
		{src: net.ParseIP("192.0.2.99"), data: []byte(wsdSampleEnvelope)},
		{src: net.ParseIP("192.0.2.42"), data: []byte("junk")},
	}
	evs := wsdEvidenceFromPackets("192.0.2.42", packets)
	if len(evs) != 1 {
		t.Fatalf("evidence count = %d, want exactly the target's own match", len(evs))
	}
	ev := evs[0]
	if ev.Source != "active:wsdiscovery" || ev.Kind != "wsdiscovery" || ev.Port != 3702 {
		t.Fatalf("evidence header = %+v", ev)
	}
	if ev.RawData["name"] != "Front Door" {
		t.Errorf("scope unpack missing in evidence: %+v", ev.RawData)
	}
}

func TestOnvifScopesTolerant(t *testing.T) {
	got := onvifScopes(`"onvif://www.onvif.org/name/Cam%2B1" "onvif://www.onvif.org/name/Second" http://example.com/other`)
	// duplicate keys keep the FIRST occurrence; foreign URIs are ignored.
	if got["name"] != "Cam+1" {
		t.Errorf("name = %q, want Cam+1 (decoded percent-escape, first occurrence wins)", got["name"])
	}
	if len(got) != 1 {
		t.Errorf("only onvif keys expected, got %+v", got)
	}
	if onvifScopes("") != nil && len(onvifScopes("")) != 0 {
		t.Errorf("empty scopes = %+v", onvifScopes(""))
	}
}
