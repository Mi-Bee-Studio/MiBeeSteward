// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package probe

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseMDNSResponse_QuestionSectionAndTruncations drives the parser's
// defensive arms: a message with a QUESTION section (skipped before the
// answers), answer rdata truncated past the message end, a name label
// running past the buffer, and a compression pointer cut in half.
func TestParseMDNSResponse_QuestionSectionAndTruncations(t *testing.T) {
	// Question-section walk: QDCOUNT=1 with a real question name, followed
	// by one A answer.
	msg := []byte{
		0x00, 0x00, // ID
		0x84, 0x00, // flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, 0x00, 0x00,
	}
	msg = append(msg, dnsName("cam.local")...)
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	aRR := dnsRR("cam.local", 1, []byte{192, 168, 63, 9})
	msg = append(msg, aRR...)

	host, _, _, hasA := ParseMDNSResponse(msg)
	require.Equal(t, "cam", host, "question section skipped, answer parsed")
	require.False(t, hasA, "hasMatchingA is always false (signature stability)")

	// Answer with rdlength far beyond the message: the record walk bails.
	bad := []byte{
		0x00, 0x00, 0x84, 0x00,
		0x00, 0x00, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, 0x00, 0x00,
	}
	bad = append(bad, dnsName("x.local")...)
	bad = append(bad, 0x00, 0x01, 0x00, 0x01) // type A, class IN
	bad = append(bad, 0, 0, 0, 120)           // ttl
	bad = append(bad, 0xFF, 0xFF)             // rdlength = 65535
	host, _, _, hasA = ParseMDNSResponse(bad)
	require.Empty(t, host, "truncated rdata yields no hostname")
	require.False(t, hasA)

	// Name label runs past the buffer: label length 9 with 3 bytes left.
	past := []byte{
		0x00, 0x00, 0x84, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x09, 'a', 'b', 'c',
	}
	host, _, _, hasA = ParseMDNSResponse(past)
	require.Empty(t, host)
	require.False(t, hasA)

	// Compression pointer as the very last byte: truncated pointer.
	ptr := []byte{
		0x00, 0x00, 0x84, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0xC0,
	}
	host, _, _, hasA = ParseMDNSResponse(ptr)
	require.Empty(t, host)
	require.False(t, hasA)
}

// TestMDNSEvidenceFromPackets_TXTAndServiceFold pins the evidence fold:
// services join into one comma-separated field and TXT pairs land as
// txt.<key> entries.
func TestMDNSEvidenceFromPackets_TXTAndServiceFold(t *testing.T) {
	ptr := dnsRR("_onvif._tcp.local", 12, dnsName("_onvif._tcp.local"))
	ptr2 := dnsRR("_rtsp._tcp.local", 12, dnsName("_rtsp._tcp.local"))
	txtRData := []byte{8}
	txtRData = append(txtRData, []byte("model=S2")...)
	txtRData = append(txtRData, 11)
	txtRData = append(txtRData, []byte("vendor=Acme")...)
	txt := dnsRR("cam._onvif._tcp.local", 16, txtRData)

	pkts := []udpPacket{{src: net.IP{192, 168, 63, 9}, data: dnsMessage(ptr, ptr2, txt)}}
	ev := mdnsEvidenceFromPackets("192.168.63.9", pkts)
	require.NotEmpty(t, ev)
	require.Equal(t, "_onvif._tcp,_rtsp._tcp", ev[0].RawData["services"])
	require.Equal(t, "S2", ev[0].RawData["txt.model"])
	require.Equal(t, "Acme", ev[0].RawData["txt.vendor"])
}
