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
	"context"
	"encoding/xml"
	"net"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// wsdTimeout bounds a single WS-Discovery Probe round. The spec (WS-Discovery
// 1.1, ONVIF Profile G baseline) has no MX-style responder contract; 2s
// matches the field behavior of camera stacks (answers typically arrive in
// tens of milliseconds) while staying a courteous share of the per-probe
// budget.
const wsdTimeout = 2 * time.Second

// wsdAddr is the WS-Discovery IPv4 multicast group + port (SOAP-over-UDP).
var wsdAddr = &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 3702}

// WSDiscoveryProbe sends a WS-Discovery Probe to the ONVIF group and collects
// ProbeMatches from ONVIF cameras/encoders/decoders and other WS-D speakers.
// It is the ACTIVE channel to the same stack the passive observer sniffs
// (eBPF kind wsdiscovery): a Probe elicits a response even from devices that
// have been quiet since boot, and the response carries the device's Types,
// Scopes (including the ONVIF name/hardware URIs) and XAddrs service URL.
//
// Name: "active:wsdiscovery". Issue #507.
type WSDiscoveryProbe struct{}

// NewWSDiscoveryProbe returns a WS-Discovery probe.
func NewWSDiscoveryProbe() *WSDiscoveryProbe { return &WSDiscoveryProbe{} }

func (p *WSDiscoveryProbe) Name() string { return "active:wsdiscovery" }

// wsdProbeMessage is a minimal, standards-shaped WS-Discovery Probe envelope.
// The fixed MessageID is fine on a scan cadence: WS-Discovery allows repeated
// Probes and cameras answer repeats idempotently.
const wsdProbeMessage = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
	`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">` +
	`<s:Header>` +
	`<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>` +
	`<a:MessageID>urn:uuid:mibee-steward-probe</a:MessageID>` +
	`<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>` +
	`</s:Header>` +
	`<s:Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/></s:Body>` +
	`</s:Envelope>`

func (p *WSDiscoveryProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	timeout := wsdTimeout
	if hint.Timeout > 0 && hint.Timeout < timeout {
		timeout = hint.Timeout
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil // soft failure (no multicast in this environment)
	}
	defer conn.Close()
	// Two datagrams, same cadence as SSDP: WS-D stacks occasionally drop the
	// first Probe while their unicast-reply path warms up.
	_, _ = conn.WriteToUDP([]byte(wsdProbeMessage), wsdAddr)
	_, _ = conn.WriteToUDP([]byte(wsdProbeMessage), wsdAddr)

	packets := readUDPMulticastResponses(conn, timeout)
	return wsdEvidenceFromPackets(ip, packets), nil
}

// wsdEvidenceFromPackets emits one "wsdiscovery" evidence per ProbeMatch
// whose SOURCE IP equals the target — the same strict filter as mDNS/SSDP:
// one multicast Probe is answered by every WS-D device on the segment, and
// without the filter a /24 scan would smear every camera's identity onto
// every host.
func wsdEvidenceFromPackets(targetIP string, packets []udpPacket) []scannerv2.Evidence {
	target := net.ParseIP(targetIP)
	var evs []scannerv2.Evidence
	for _, pkt := range packets {
		if !pkt.src.Equal(target) {
			continue
		}
		raw := parseWSDiscoveryMatch(pkt.data)
		if len(raw) == 0 {
			continue
		}
		evs = append(evs, scannerv2.Evidence{
			Source:     "active:wsdiscovery",
			Kind:       "wsdiscovery",
			IP:         targetIP,
			Protocol:   "udp",
			Port:       3702,
			RawData:    raw,
			Confidence: 0.85,
			ObservedAt: time.Now(),
		})
	}
	return evs
}

// wsdEnvelope is the decoding shape of a SOAP-over-UDP ProbeMatches envelope.
// Namespaces are declared per-document by the responder; matching by local
// name via the space-prefixed tags keeps the parser tolerant of the prefix
// zoo seen in the wild (s:/soap:, d:/wsd:, td: for ONVIF device service...).
type wsdEnvelope struct {
	Body struct {
		ProbeMatches []struct {
			ProbeMatch []struct {
				Types  string `xml:"Types"`
				Scopes struct {
					Value string `xml:"value,attr"`
				} `xml:"Scopes"`
				XAddrs  string `xml:"XAddrs"`
				Address string `xml:"EndpointReference>Address"`
			} `xml:"ProbeMatch"`
		} `xml:"ProbeMatches"`
	} `xml:"Body"`
}

// parseWSDiscoveryMatch extracts the identity fields from one ProbeMatches
// datagram. Returns nil for anything that is not a usable match (no Types,
// no Scopes, no XAddrs — a bare envelope contributes nothing). The ONVIF
// scope URIs are unpacked: onvif://www.onvif.org/name/Front Door becomes
// raw["name"]="Front Door" (URL-unescaping handled by the scope walker),
// giving the corpus a direct brand/model channel.
func parseWSDiscoveryMatch(pkt []byte) map[string]string {
	// Cheap pre-check before the XML decoder: WS-D responses always carry a
	// ProbeMatches element; Hello/Bye/ResolveMatches are ignored.
	if !strings.Contains(string(pkt), "ProbeMatch") {
		return nil
	}
	var env wsdEnvelope
	if err := xml.Unmarshal(pkt, &env); err != nil {
		return nil
	}
	raw := map[string]string{}
	for _, pm := range env.Body.ProbeMatches {
		for _, m := range pm.ProbeMatch {
			if m.Types != "" && raw["types"] == "" {
				raw["types"] = m.Types
			}
			if m.Scopes.Value != "" && raw["scopes"] == "" {
				raw["scopes"] = m.Scopes.Value
			}
			if m.XAddrs != "" && raw["xaddrs"] == "" {
				raw["xaddrs"] = m.XAddrs
			}
			if m.Address != "" && raw["address"] == "" {
				raw["address"] = m.Address
			}
		}
	}
	// Unpack the ONVIF scope URIs into direct keys (name/hardware/model are
	// the high-signal ones the corpus matches on).
	for k, v := range onvifScopes(raw["scopes"]) {
		if _, exists := raw[k]; !exists {
			raw[k] = v
		}
	}
	if len(raw) == 0 {
		return nil
	}
	raw["service_hint"] = "onvif"
	return raw
}

// onvifScopes walks a WS-D Scopes attribute (a quoted-URI list) and extracts
// the ONVIF-defined URIs: onvif://www.onvif.org/<key>/<url-escaped value>.
// The values are percent-decoded (camera names carry spaces as %20).
func onvifScopes(scopes string) map[string]string {
	out := map[string]string{}
	for _, tok := range strings.Fields(scopes) {
		tok = strings.Trim(tok, "\"")
		const prefix = "onvif://www.onvif.org/"
		rest, ok := strings.CutPrefix(tok, prefix)
		if !ok {
			continue
		}
		key, value, ok := strings.Cut(rest, "/")
		if !ok || value == "" {
			continue
		}
		if _, dup := out[key]; !dup {
			out[key] = unescapeScope(value)
		}
	}
	return out
}

// unescapeScope decodes %XX sequences in an ONVIF scope value (the spec
// URL-escapes the free-text segments).
func unescapeScope(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
