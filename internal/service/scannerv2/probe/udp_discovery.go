// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// ---------------------------------------------------------------------------
// Shared UDP discovery helpers
// ---------------------------------------------------------------------------

// mdnsTimeout bounds a single mDNS multicast query round.
const mdnsTimeout = 3 * time.Second

// ssdpTimeout bounds a single SSDP M-SEARCH round.
const ssdpTimeout = 3 * time.Second

// netbiosTimeout bounds a single NetBIOS Name-Service query.
const netbiosTimeout = 3 * time.Second

// readUDPMulticastResponses drains a UDP socket for up to timeout, returning
// every packet received along with its source IP. Used by mDNS/SSDP where
// multiple devices may answer a single multicast query — the caller MUST filter
// to packets whose source IP equals the target, otherwise cross-talk makes
// every host appear to speak every other host's services.
type udpPacket struct {
	src  net.IP
	data []byte
}

func readUDPMulticastResponses(conn *net.UDPConn, timeout time.Duration) []udpPacket {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var out []udpPacket
	for {
		buf := make([]byte, 9000)
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		out = append(out, udpPacket{src: src.IP, data: buf[:n]})
	}
}

// ---------------------------------------------------------------------------
// mDNS probe (RFC 6762) — multicast DNS on 224.0.0.251:5353
// ---------------------------------------------------------------------------

// mdnsAddr is the mDNS IPv4 multicast group + port.
var mdnsAddr = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// MDNSProbe sends a multicast DNS query for common service types and listens
// for unicast responses from devices on the local segment. mDNS is how most
// cameras/IoT printers/Apple devices publish their name + services without
// needing a DNS server.
//
// The probe queries the service-enumeration PTR (_services._dns-sd._udp.local)
// plus a curated set of camera/IoT service types (_onvif._tcp, _rtsp._tcp,
// _http._tcp, _airplay._tcp, _googlecast._tcp). Responses that originate from
// the target IP yield an "mdns" evidence with the discovered hostname/service.
//
// Name: "active:mdns".
type MDNSProbe struct{}

// NewMDNSProbe returns an mDNS probe.
func NewMDNSProbe() *MDNSProbe { return &MDNSProbe{} }

func (p *MDNSProbe) Name() string { return "active:mdns" }

// mdnsQueryTypes are the service PTR names queried. The first is the global
// service-enumeration record; the rest are the high-value camera/IoT types.
var mdnsQueryTypes = []string{
	"_services._dns-sd._udp.local",
	"_onvif._tcp.local",
	"_rtsp._tcp.local",
	"_http._tcp.local",
	"_airplay._tcp.local",
	"_googlecast._tcp.local",
	"_smb._tcp.local",
	"_ssh._tcp.local",
}

func (p *MDNSProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	timeout := mdnsTimeout
	if hint.Timeout > 0 && hint.Timeout < timeout {
		timeout = hint.Timeout
	}
	// Open a UDP socket bound to any port; we'll send to the multicast group
	// and read back unicast replies. Multicast send requires no special
	// privileges on Linux when IP_MULTICAST_LOOP is left at default.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		// Multicast may be unavailable in some sandboxes (no routable IPv4
		// multicast). This is a soft failure — no mDNS evidence, not a scan error.
		return nil, nil
	}
	defer conn.Close()

	// Send each query. Build one DNS message per query type (mDNS allows
	// multiple questions per message, but many embedded responders only answer
	// the first, so we keep them separate for reliability).
	for _, qname := range mdnsQueryTypes {
		msg := buildMDNSQuery(qname)
		_, _ = conn.WriteToUDP(msg, mdnsAddr)
	}

	// Collect responses for the timeout window. CRITICAL: filter to packets
	// whose SOURCE IP equals the target — mDNS is multicast, so a query for
	// host X receives replies from EVERY mDNS responder on the segment. Without
	// this filter, every host in a /24 scan inherits every other host's mDNS
	// identity (false-positive liveness + wrong vendor/hostname).
	packets := readUDPMulticastResponses(conn, timeout)
	return mdnsEvidenceFromPackets(ip, packets), nil
}

// buildMDNSQuery constructs a minimal mDNS query message: header with one
// question, no compression. QR=0 (query), opcode=0, RD=0.
func buildMDNSQuery(name string) []byte {
	// Header: ID=0 (mDNS), flags=0, QDCOUNT=1, rest=0.
	msg := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	// QNAME: label-length-prefixed, terminated by 0.
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0)
	// QTYPE=PTR (12), QCLASS=IN (1) with cache-flush bit (0x8000) per mDNS.
	msg = append(msg, 0, 12, 0x80, 1)
	return msg
}

// mdnsEvidenceFromPackets parses the collected mDNS responses and emits one
// "mdns" evidence per packet WHOSE SOURCE IP equals the target. The source-IP
// filter is what keeps a /24 scan from attributing one device's mDNS identity
// to every other host — mDNS responses arrive from whoever answers, not from
// the IP we queried.
func mdnsEvidenceFromPackets(targetIP string, packets []udpPacket) []scannerv2.Evidence {
	target := net.ParseIP(targetIP)
	var evs []scannerv2.Evidence
	for _, pkt := range packets {
		// Only accept replies that actually came from the target host. Replies
		// from other responders are cross-talk and must be dropped.
		if !pkt.src.Equal(target) {
			continue
		}
		host, services, txtKV, _ := parseMDNSResponse(pkt.data)
		if host == "" && len(services) == 0 {
			continue
		}
		raw := map[string]string{}
		if host != "" {
			raw["hostname"] = host
		}
		if len(services) > 0 {
			raw["services"] = strings.Join(services, ",")
		}
		for k, v := range txtKV {
			// TXT keys like "model", "vendor", "serial" are high-signal; keep
			// them under namespaced keys.
			raw["txt."+k] = v
		}
		if len(raw) == 0 {
			continue
		}
		evs = append(evs, scannerv2.Evidence{
			Source:     "active:mdns",
			Kind:       "mdns",
			IP:         targetIP,
			Protocol:   "udp",
			Port:       5353,
			RawData:    raw,
			Confidence: 0.85,
			ObservedAt: time.Now(),
		})
	}
	return evs
}

// parseMDNSResponse walks a DNS response message and extracts the A-record
// hostname, the set of service PTR names, and a map of TXT key=value records.
// The source-IP filter in mdnsEvidenceFromPackets already guarantees this
// packet came from the target, so we don't need to re-match by address here —
// hasMatchingA is kept (always false now) only for signature stability.
func parseMDNSResponse(msg []byte) (hostname string, services []string, txtKV map[string]string, hasMatchingA bool) {
	if len(msg) < 12 {
		return
	}
	ancount := int(msg[6])<<8 | int(msg[7])
	if ancount == 0 {
		return
	}
	txtKV = map[string]string{}
	pos := 12
	// Skip the question section (QNAME + 4 bytes type/class). We don't know
	// QDCOUNT-derived skip precisely without parsing, but responses to our
	// queries have QDCOUNT=0 (mDNS unicast responses drop the question).
	qdcount := int(msg[4])<<8 | int(msg[5])
	for i := 0; i < qdcount && pos < len(msg); i++ {
		_, npos, err := readDNSName(msg, pos)
		if err != nil {
			return
		}
		pos = npos + 4 // type(2) + class(2)
	}
	// Walk the answer records.
	for i := 0; i < ancount && pos+10 < len(msg); i++ {
		name, npos, err := readDNSName(msg, pos)
		if err != nil {
			return
		}
		pos = npos
		if pos+10 > len(msg) {
			return
		}
		rtype := int(msg[pos])<<8 | int(msg[pos+1])
		rdlen := int(msg[pos+8])<<8 | int(msg[pos+9])
		pos += 10
		if pos+rdlen > len(msg) {
			return
		}
		rdata := msg[pos : pos+rdlen]
		switch rtype {
		case 1: // A — record owner name is the device hostname
			if rdlen == 4 && hostname == "" {
				hostname = dnsStripLocal(name)
			}
		case 12: // PTR — service name (e.g. "_onvif._tcp.local")
			if ptr, _, err := readDNSName(msg, pos); err == nil {
				s := dnsStripLocal(ptr)
				if s != "" {
					services = append(services, s)
				}
			}
		case 16: // TXT — key=value pairs (record owner is the service instance,
			// NOT the device hostname — do not set hostname from it, or it'll
			// look like "NanoPiR4S._smb._tcp").
			for tpos := 0; tpos < len(rdata); {
				tlen := int(rdata[tpos])
				if tpos+1+tlen > len(rdata) {
					break
				}
				pair := string(rdata[tpos+1 : tpos+1+tlen])
				if eq := strings.IndexByte(pair, '='); eq > 0 {
					k := strings.ToLower(pair[:eq])
					v := pair[eq+1:]
					// Keep only the high-signal keys to avoid noise.
					switch k {
					case "model", "vendor", "manufacturer", "serial", "fqdn", "nm", "ty", "md":
						txtKV[k] = v
					}
				}
				tpos += 1 + tlen
			}
		case 33: // SRV — the target host is the device, but the owner name is a
			// service instance ("foo._smb._tcp"). Only derive a hostname from
			// the SRV target (the device FQDN), never from the owner name.
			if rdlen >= 6 {
				if srv, _, err := readDNSName(msg, pos+6); err == nil {
					// SRV target is "<host>.local" — strip the .local suffix.
					// Don't overwrite a hostname already set by an A record.
					if stripped := dnsStripLocal(srv); stripped != "" && hostname == "" && !strings.HasPrefix(stripped, "_") {
						hostname = stripped
					}
				}
			}
		}
		pos += rdlen
	}
	return
}

// readDNSName reads a (possibly compressed) DNS name starting at pos. Returns
// the dotted name and the position just past the name (NOT past the type/class
// that usually follows — callers add 4 themselves). Handles message
// compression pointers (RFC 1035 sec 4.1.4).
func readDNSName(msg []byte, pos int) (string, int, error) {
	var labels []string
	jumped := false
	next := pos
	for steps := 0; steps < 128; steps++ { // loop bound guards against malicious cycles
		if pos >= len(msg) {
			return "", 0, fmt.Errorf("dns name out of bounds")
		}
		b := msg[pos]
		if b == 0 {
			pos++
			if !jumped {
				next = pos
			}
			break
		}
		if b&0xC0 == 0xC0 { // compression pointer
			if pos+1 >= len(msg) {
				return "", 0, fmt.Errorf("dns pointer truncated")
			}
			ptr := int(b&0x3F)<<8 | int(msg[pos+1])
			if !jumped {
				next = pos + 2
			}
			pos = ptr
			jumped = true
			continue
		}
		if pos+1+int(b) > len(msg) {
			return "", 0, fmt.Errorf("dns label out of bounds")
		}
		labels = append(labels, string(msg[pos+1:pos+1+int(b)]))
		pos += 1 + int(b)
	}
	return strings.Join(labels, "."), next, nil
}

// dnsStripLocal removes the trailing ".local" suffix and collapses to the
// first label for display ("cam-front.local" → "cam-front",
// "_onvif._tcp.local" → "_onvif._tcp").
func dnsStripLocal(name string) string {
	name = strings.TrimSuffix(name, ".local")
	name = strings.TrimSuffix(name, ".")
	return name
}

// ---------------------------------------------------------------------------
// SSDP / UPnP probe — HTTP-over-UDP on 239.255.255.250:1900
// ---------------------------------------------------------------------------

// ssdpAddr is the SSDP IPv4 multicast group + port.
var ssdpAddr = &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}

// SSDPProbe sends an M-SEARCH for ssdp:all and collects UPnP responses. Routers,
// smart TVs, IPTV boxes, and many IoT devices answer with a SERVER header that
// names the OS/firmware, which is far more specific than OUI.
//
// Name: "active:ssdp".
type SSDPProbe struct{}

// NewSSDPProbe returns an SSDP probe.
func NewSSDPProbe() *SSDPProbe { return &SSDPProbe{} }

func (p *SSDPProbe) Name() string { return "active:ssdp" }

// ssdpMSearch is the canonical discovery datagram (RFC? simple service discovery).
const ssdpMSearch = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n" +
	"ST: ssdp:all\r\n" +
	"\r\n"

func (p *SSDPProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	timeout := ssdpTimeout
	if hint.Timeout > 0 && hint.Timeout < timeout {
		timeout = hint.Timeout
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil // soft failure (no multicast)
	}
	defer conn.Close()
	// Send a couple of M-SEARCH datagrams; SSDP devices occasionally drop one.
	_, _ = conn.WriteToUDP([]byte(ssdpMSearch), ssdpAddr)
	_, _ = conn.WriteToUDP([]byte(ssdpMSearch), ssdpAddr)

	packets := readUDPMulticastResponses(conn, timeout)
	var evs []scannerv2.Evidence
	target := net.ParseIP(ip)
	for _, pkt := range packets {
		// SSDP is multicast: a single M-SEARCH is answered by every UPnP
		// responder on the segment. Only count replies from the target IP, or
		// this probe would make every host inherit every other host's UPnP
		// identity.
		if !pkt.src.Equal(target) {
			continue
		}
		raw := parseSSDPResponse(pkt.data)
		if len(raw) >= 2 { // require at least SERVER or LOCATION besides status
			evs = append(evs, scannerv2.Evidence{
				Source:     "active:ssdp",
				Kind:       "ssdp",
				IP:         ip,
				Protocol:   "udp",
				Port:       1900,
				RawData:    raw,
				Confidence: 0.8,
				ObservedAt: time.Now(),
			})
		}
	}
	return evs, nil
}

// parseSSDPResponse extracts the headers we care about from an M-SEARCH reply.
// SSDP responses look like:
//
//	HTTP/1.1 200 OK
//	LOCATION: http://192.168.63.40:50000/desc.xml
//	SERVER: Linux/4.4 UPnP/1.1 MyDevice/1.0
//	ST: upnp:rootdevice
//
// The SERVER header is the high-value field (often carries OS + product + version).
func parseSSDPResponse(pkt []byte) map[string]string {
	raw := map[string]string{}
	for _, line := range strings.Split(string(pkt), "\r\n") {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		if val == "" {
			continue
		}
		switch key {
		case "SERVER":
			raw["server"] = val
		case "LOCATION":
			raw["location"] = val
		case "ST", "NT": // service/target type
			raw["st"] = val
		case "USN": // unique service name
			raw["usn"] = val
		}
	}
	return raw
}

// ---------------------------------------------------------------------------
// NetBIOS Name Service probe — UDP 137 (NBNS, RFC 1002)
// ---------------------------------------------------------------------------

// netbiosNSAddr is the Well-Known NBNS port. Unlike mDNS/SSDP, NBNS is a
// unicast query to the target's port 137 (not multicast), so it works
// cross-subnet as long as UDP 137 is reachable.
var netbiosNSPort = 137

// NetBIOSProbe sends a Node Status Request (NBNS) to UDP 137 and parses the
// returned names. This is the primary way to identify Windows hosts (which
// often run no SNMP/mDNS) and their workgroup/domain.
//
// Name: "active:netbios".
type NetBIOSProbe struct{}

// NewNetBIOSProbe returns a NetBIOS probe.
func NewNetBIOSProbe() *NetBIOSProbe { return &NetBIOSProbe{} }

func (p *NetBIOSProbe) Name() string { return "active:netbios" }

// buildNetbiosStatusQuery constructs a NetBIOS Node Status Request packet. The
// queried name is "*" (wildcard) which returns all names the node knows. The
// transaction ID is fixed (NBNS doesn't require it to vary for a status query).
func buildNetbiosStatusQuery() []byte {
	// Header: TID=0x1337, flags=0x0010 (broadcast, name service), questions=1,
	// answers=0, authority=0, additional=0.
	msg := []byte{0x13, 0x37, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// Encoded name: length 32, "*" padded with spaces, name-type 0x00, then a
	// zero-length second label, then type=NBSTAT (0x21), class=IN (0x01).
	name := encodeNetbiosName("*", 0x00)
	msg = append(msg, byte(len(name)))
	msg = append(msg, name...)
	msg = append(msg, 0)          // root label terminator
	msg = append(msg, 0x00, 0x21) // type NBSTAT
	msg = append(msg, 0x00, 0x01) // class IN
	return msg
}

// encodeNetbiosName applies the RFC 1002 first-level encoding: each byte is
// split into two nibbles, each nibble has 'A' added. So "*" (0x2A) becomes
// "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (32 chars), then the suffix byte.
func encodeNetbiosName(name string, suffix byte) []byte {
	// Pad/truncate to 15 chars (NetBIOS names are 16 bytes: 15 + suffix).
	padded := make([]byte, 15)
	for i := range padded {
		padded[i] = ' '
	}
	copy(padded, name)
	out := make([]byte, 0, 34)
	for _, b := range padded {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0F))
	}
	out = append(out, 'A'+(suffix>>4), 'A'+(suffix&0x0F))
	return out
}

func (p *NetBIOSProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	if ctx.Err() != nil {
		return nil, nil
	}
	timeout := netbiosTimeout
	if hint.Timeout > 0 && hint.Timeout < timeout {
		timeout = hint.Timeout
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, strconv.Itoa(netbiosNSPort)), timeout)
	if err != nil {
		return nil, nil // UDP 137 closed/unreachable — fine
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(buildNetbiosStatusQuery()); err != nil {
		return nil, nil
	}
	resp := make([]byte, 1500)
	n, err := conn.Read(resp)
	if err != nil || n < 57 { // minimum NBNS response header
		return nil, nil
	}
	host, workgroup := parseNetbiosResponse(resp[:n])
	if host == "" && workgroup == "" {
		return nil, nil
	}
	raw := map[string]string{}
	if host != "" {
		raw["hostname"] = host
	}
	if workgroup != "" {
		raw["workgroup"] = workgroup
	}
	return []scannerv2.Evidence{{
		Source:     "active:netbios",
		Kind:       "netbios",
		IP:         ip,
		Protocol:   "udp",
		Port:       137,
		RawData:    raw,
		Confidence: 0.9,
		ObservedAt: time.Now(),
	}}, nil
}

// parseNetbiosResponse extracts the workstation name (suffix 0x00, not the
// workgroup) and the domain/workgroup name (suffix 0x00 with the GROUP flag)
// from a Node Status Response. The response body after the header carries the
// MAC address as the final 6 bytes — we return that too via the caller.
func parseNetbiosResponse(msg []byte) (host, workgroup string) {
	if len(msg) < 57 {
		return
	}
	// num_names = msg[56]
	numNames := int(msg[56])
	pos := 57
	for i := 0; i < numNames && pos+18 <= len(msg); i++ {
		entry := msg[pos : pos+18]
		pos += 18
		name := strings.TrimRight(string(entry[:15]), " ")
		suffix := entry[15]
		flags := uint16(entry[16])<<8 | uint16(entry[17])
		isGroup := flags&0x8000 != 0 // group-name bit
		// suffix 0x00 = workstation / domain. The non-group one is the hostname.
		if suffix == 0x00 {
			if isGroup {
				if workgroup == "" {
					workgroup = name
				}
			} else {
				if host == "" {
					host = name
				}
			}
		}
	}
	return
}
