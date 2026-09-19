// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestMDNSProbe_LoopbackRealSend pins the real send/receive path: a local UDP
// listener on 5353 answers the unicast query (UnicastQueries mode), the probe
// accepts the reply because the SOURCE ip matches the target (127.0.0.1), and
// the evidence carries the parsed hostname. Cross-talk (a reply from a
// different source) is dropped.
func TestMDNSProbe_LoopbackRealSend(t *testing.T) {
	// A responder on 127.0.0.1:5353 that answers any datagram with a valid
	// mDNS response carrying an A record for "cam.local".
	resp := dnsMessage(dnsRR("cam.local", 1, []byte{127, 0, 0, 1}))
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353})
	if err != nil {
		t.Skipf("5353 unavailable on this host: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = n
			_, _ = ln.WriteToUDP(resp, from)
		}
	}()

	p := NewMDNSProbeWithConfig(MDNSConfig{UnicastQueries: true})
	evs, err := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Timeout: 2 * time.Second})
	require.NoError(t, err)
	require.NotEmpty(t, evs, "unicast reply from the target must yield evidence")
	require.Equal(t, "cam", evs[0].RawData["hostname"], ".local is stripped")
}

// TestSSDPProbe_LoopbackRealSend: an SSDP responder on 1900 answering with
// SERVER/NT headers; the probe's evidence carries them.
func TestSSDPProbe_LoopbackRealSend(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice\r\nSERVER: Linux/4.4 UPnP/1.1 Router/1.0\r\n\r\n")
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1900})
	if err != nil {
		t.Skipf("1900 unavailable on this host: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			_, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = ln.WriteToUDP(resp, from)
		}
	}()

	evs, err := (&SSDPProbe{}).Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Timeout: 2 * time.Second})
	require.NoError(t, err)
	require.NotEmpty(t, evs)
}

// TestMDNSEvidenceFromPackets_CrossTalkDropped pins the source filter: replies
// from a NON-target source never become evidence even when well-formed.
func TestMDNSEvidenceFromPackets_CrossTalkDropped(t *testing.T) {
	pkt := udpPacket{src: net.ParseIP("10.0.0.99"), data: dnsMessage(dnsRR("intruder.local", 1, []byte{10, 0, 0, 99}))}
	require.Empty(t, mdnsEvidenceFromPackets("10.0.0.1", []udpPacket{pkt}))

	ok := udpPacket{src: net.ParseIP("10.0.0.1"), data: dnsMessage(dnsRR("real.local", 1, []byte{10, 0, 0, 1}))}
	evs := mdnsEvidenceFromPackets("10.0.0.1", []udpPacket{ok})
	require.Len(t, evs, 1)
	require.Equal(t, "real", evs[0].RawData["hostname"], ".local is stripped")

	// Garbage payload from the right source → no evidence.
	garbage := udpPacket{src: net.ParseIP("10.0.0.1"), data: []byte("not dns at all")}
	require.Empty(t, mdnsEvidenceFromPackets("10.0.0.1", []udpPacket{garbage}))
}
