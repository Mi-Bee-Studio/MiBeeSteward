// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import "testing"

// The description-XML fetch guards and parser, pinned (#506).

func TestValidateSSDPLocation(t *testing.T) {
	target := "192.0.2.10"
	ok := []string{
		"http://192.0.2.10:5000/rootDesc.xml",
		"http://192.0.2.10/desc.xml",
		"https://192.0.2.10:8443/desc.xml",
	}
	bad := []string{
		"http://192.0.2.99:5000/rootDesc.xml", // another host: SSRF guard
		"http://router.local/rootDesc.xml",    // DNS name, not the device IP
		"ftp://192.0.2.10/desc.xml",           // non-HTTP scheme
		"192.0.2.10",                          // not a URL
		"",                                    // empty
		"http://[::1]/desc.xml",               // v6 literal mismatch
	}
	for _, u := range ok {
		if !validateSSDPLocation(u, target) {
			t.Errorf("want accepted: %q", u)
		}
	}
	for _, u := range bad {
		if validateSSDPLocation(u, target) {
			t.Errorf("want refused: %q", u)
		}
	}
}

const upnpDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType>
    <friendlyName>Lunzn R68S Router</friendlyName>
    <manufacturer>Lunzn</manufacturer>
    <manufacturerURL>http://www.lunzn.com/</manufacturerURL>
    <modelDescription>FastRhino R68S soft router</modelDescription>
    <modelName>R68S</modelName>
    <modelNumber>1.0</modelNumber>
    <UDN>uuid:2fac1234-31f8-11b4-a222-08002b34c003</UDN>
  </device>
</root>`

func TestParseUPnPDescription(t *testing.T) {
	d := parseUPnPDescription([]byte(upnpDescXML))
	if d == nil {
		t.Fatal("description should parse")
	}
	want := map[string]string{
		"friendly_name":     "Lunzn R68S Router",
		"manufacturer":      "Lunzn",
		"model_name":        "R68S",
		"model_number":      "1.0",
		"model_description": "FastRhino R68S soft router",
		"udn":               "uuid:2fac1234-31f8-11b4-a222-08002b34c003",
		"device_type":       "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %q, want %q", k, d[k], v)
		}
	}
}

func TestParseUPnPDescriptionRejectsNonDevice(t *testing.T) {
	if d := parseUPnPDescription([]byte("<html><body>404</body></html>")); d != nil {
		t.Fatalf("non-description must yield nil, got %v", d)
	}
	if d := parseUPnPDescription([]byte("not xml")); d != nil {
		t.Fatalf("garbage must yield nil, got %v", d)
	}
	// device node without any identity fields → nil (nothing to keep)
	if d := parseUPnPDescription([]byte("<root><device><serviceList/></device></root>")); d != nil {
		t.Fatalf("empty device node must yield nil, got %v", d)
	}
}
