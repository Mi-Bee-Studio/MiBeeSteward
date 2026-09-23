// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// --- parseSSDPResponse ---

// The basic SSDP header extraction has its own test in udp_discovery_test.go;
// this one pins the extended surface: NT-vs-ST bucket sharing, USN, and the
// skip rules, via the exported wrapper the passive listener uses (#377).
func TestParseSSDPResponse_ExtendedHeaders(t *testing.T) {
	pkt := []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"SERVER: Linux/5.15 UPnP/1.0 MiniUPnPd/2.2.1\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"NT: uuid:2fac1234-31f8-11b4-a222-08002b34c003\r\n" +
		"USN: uuid:2fac1234-31f8-11b4-a222-08002b34c003::upnp:rootdevice\r\n" +
		"EMPTY-HEADER: \r\n" +
		"junk-without-colon\r\n")

	raw := ParseSSDPResponse(pkt)
	require.Equal(t, "Linux/5.15 UPnP/1.0 MiniUPnPd/2.2.1", raw["server"])
	require.Equal(t, "uuid:2fac1234-31f8-11b4-a222-08002b34c003::upnp:rootdevice", raw["usn"])
	// ST and NT share one bucket (st), the later line wins.
	require.Equal(t, "uuid:2fac1234-31f8-11b4-a222-08002b34c003", raw["st"])
	// Empty-valued headers and colon-less lines are skipped, and keys outside
	// the keep-list never land in the map.
	require.NotContains(t, raw, "cache-control")
	require.NotContains(t, raw, "empty-header")

	require.Empty(t, ParseSSDPResponse([]byte("garbage")))
	require.Empty(t, ParseSSDPResponse(nil))
}

// --- parseMDNSResponse ---

// dnsName encodes a dotted name as DNS label bytes (no compression).
func dnsName(name string) []byte {
	out := []byte{}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return append(out, 0)
}

// dnsRR builds one answer record: name + type + class + ttl + rdlen + rdata.
func dnsRR(name string, rtype uint16, rdata []byte) []byte {
	rr := dnsName(name)
	rr = append(rr, byte(rtype>>8), byte(rtype))           // type
	rr = append(rr, 0x00, 0x01)                            // class IN
	rr = append(rr, 0, 0, 0, 120)                          // ttl
	rr = append(rr, byte(len(rdata)>>8), byte(len(rdata))) // rdlength
	return append(rr, rdata...)
}

// dnsMessage assembles a response with QDCOUNT=0 and the given answers.
func dnsMessage(answers ...[]byte) []byte {
	msg := []byte{
		0x00, 0x00, // ID
		0x84, 0x00, // flags: response + authoritative
		0x00, 0x00, // QDCOUNT
		byte(len(answers) >> 8), byte(len(answers)), // ANCOUNT
		0x00, 0x00, 0x00, 0x00,
	}
	for _, a := range answers {
		msg = append(msg, a...)
	}
	return msg
}

func TestParseMDNSResponse_Records(t *testing.T) {
	// A record (type 1) → hostname, .local stripped.
	aRR := dnsRR("nas.local", 1, []byte{192, 168, 63, 5})
	// PTR record (type 12) → service name; rdata is itself a DNS name.
	ptrRR := dnsRR("_onvif._tcp.local", 12, dnsName("_onvif._tcp.local"))
	// TXT record (type 16): length-prefixed pairs; high-signal keys kept.
	txtRData := []byte{9}
	txtRData = append(txtRData, []byte("model=X10")...)
	txtRData = append(txtRData, 16)
	txtRData = append(txtRData, []byte("vendor=Hikvision")...)
	txtRData = append(txtRData, 11)
	txtRData = append(txtRData, []byte("ignore=me!")...)
	txtRR := dnsRR("nas._onvif._tcp.local", 16, txtRData)

	host, services, txt, hasA := ParseMDNSResponse(dnsMessage(aRR, ptrRR, txtRR))
	require.Equal(t, "nas", host)
	require.Equal(t, []string{"_onvif._tcp"}, services)
	require.Equal(t, map[string]string{"model": "X10", "vendor": "Hikvision"}, txt)
	require.False(t, hasA) // matching-A check is disabled by design (see func comment)
}

func TestParseMDNSResponse_SRVTargetHostname(t *testing.T) {
	// No A record: the SRV target (at rdata offset 6 after pri/weight/port)
	// becomes the hostname when it doesn't start with "_".
	srvRData := []byte{0, 0, 0, 0, 0, 80} // priority, weight, port=80
	srvRData = append(srvRData, dnsName("nanopi-r4s.local")...)
	srvRR := dnsRR("smb._tcp.local", 33, srvRData)

	host, _, _, _ := ParseMDNSResponse(dnsMessage(srvRR))
	require.Equal(t, "nanopi-r4s", host)
}

func TestParseMDNSResponse_MalformedAndEmpty(t *testing.T) {
	// Too short / zero answers → zero values.
	host, services, txt, _ := ParseMDNSResponse([]byte{1, 2, 3})
	require.Empty(t, host)
	require.Nil(t, services)
	require.Nil(t, txt)
	_, services, _, _ = ParseMDNSResponse(dnsMessage())
	require.Empty(t, services)

	// Truncated record (rdlength overruns the buffer) → safe zero-value return,
	// no panic. The first answer (valid A) is consumed, the second is cut off.
	good := dnsRR("nas.local", 1, []byte{10, 0, 0, 1})
	bad := append(dnsName("x.local"), 0, 1, 0, 1, 0, 0, 0, 120, 0xFF, 0xFF) // rdlen=65535
	host, _, _, _ = ParseMDNSResponse(dnsMessage(good, bad))
	require.Equal(t, "nas", host)

	// SRV with rdlen < 6 is skipped without deriving a hostname.
	require.Equal(t, "", func() string {
		h, _, _, _ := ParseMDNSResponse(dnsMessage(dnsRR("_s._tcp.local", 33, []byte{1, 2, 3})))
		return h
	}())
}
