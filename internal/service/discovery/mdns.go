// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ServiceType is the DNS-SD service type this instance announces on the LAN
// (Scout docs/02 §8.4 type registry row for steward). The App pre-registers
// this name in its mDNS browser; changing it breaks discovery.
const ServiceType = "_mibee-steward._tcp"

// mDNS wire constants (RFC 6762/6763): the multicast group and port every
// resolver shares.
const (
	mdnsGroupV4  = "224.0.0.251"
	mdnsPort     = 5353
	mdnsTTLPtr   = 4500 // service type discovery record, RFC 6762 §10 stable
	mdnsTTLRec   = 120  // SRV/TXT/A, RFC 6762 §10 volatile default
	mdnsReadBuf  = 1500 // mDNS packets must fit one link MTU
	mdnsDeadline = time.Second
)

// announceBursts is the number of unsolicited announcements at startup
// (RFC 6762 §8.1 recommends at least two, spaced ≥1s), so already-running
// resolvers (avahi, Scout's NSD) pick the service up without re-browsing.
const announceBursts = 3

// TXTRecords builds the DNS-SD TXT entries in the exact shape NVR's
// _mibee-nvr._tcp uses (Scout docs/02 §3/§8.2): ver/id/name/tls/api. The App
// resolves the same five keys for every MiBee service, so the shape is a
// cross-repo contract — the name value is URL-escaped to survive arbitrary
// UTF-8 instance names in raw TXT strings.
func TXTRecords(id, name string, apiPort int, tls bool) []string {
	tlsFlag := "0"
	if tls {
		tlsFlag = "1"
	}
	return []string{
		"ver=1",
		"id=" + id,
		"name=" + url.QueryEscape(name),
		"tls=" + tlsFlag,
		"api=" + strconv.Itoa(apiPort),
	}
}

// Registrar answers mDNS queries for this instance so LAN clients (the Scout
// app's NSD browse, avahi, ...) can discover it without subnet scanning. It
// is the fast path of the discovery trio; the UDP responder (responder.go)
// is the fallback for multicast-restricted networks.
//
// Conformance notes (RFC 6762): answers to ordinary multicast (QM) queries
// go back to the multicast group; only legacy one-shot queries (source port
// ≠ 5353) get a unicast reply with the query's transaction ID echoed. The
// hashicorp/mdns library replies unicast to EVERY query — real resolvers
// (avahi-daemon verified on the test rig, #729) silently drop such
// responses, which is why this is a hand-rolled responder instead of the
// library. The socket discipline matches the scanner's passive mDNS listener
// (SO_REUSEADDR + IP_ADD_MEMBERSHIP, NO SO_REUSEPORT — reuseport would split
// datagrams with avahi/systemd-resolved): the two coexist by construction and
// the passive evidence listener keeps receiving while we announce.
type Registrar struct {
	serviceFQDN  string // "_mibee-steward._tcp.local."
	instanceFQDN string // "<name>._mibee-steward._tcp.local."
	hostFQDN     string // "<hostname>.local."
	txt          []string
	port         int
	ips          []net.IP

	mu   sync.Mutex
	conn *net.UDPConn
	stop chan struct{}
	wg   sync.WaitGroup
}

// NewRegistrar builds a registrar for the given identity. apiPort is the
// HTTP API port (cfg.Server.Port); tls is the announced scheme hint (see
// AnnounceConfig.TLS).
func NewRegistrar(id, name string, apiPort int, tls bool) *Registrar {
	host, _ := osHostname()
	return &Registrar{
		serviceFQDN:  dnsName(ServiceType + ".local"),
		instanceFQDN: dnsName(name + "." + ServiceType + ".local"),
		hostFQDN:     dnsName(host + ".local"),
		txt:          TXTRecords(id, name, apiPort, tls),
		port:         apiPort,
	}
}

// Start joins the mDNS group on every multicast-capable interface, spawns
// the query loop and the startup announcement burst. A bind failure (a
// system resolver stack refusing the share despite SO_REUSEADDR) is
// returned; the routes wiring logs it once and continues without mDNS —
// discovery must not block boot (snmptrap posture).
func (m *Registrar) Start() error {
	return m.startOn("0.0.0.0:" + strconv.Itoa(mdnsPort))
}

// startOn is the bind seam (tests pin loopback ephemeral ports; production
// binds the fixed 0.0.0.0:5353).
func (m *Registrar) startOn(addr string) error {
	lc := net.ListenConfig{Control: mdnsJoinControl(mdnsGroupV4)}
	conn, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return fmt.Errorf("listen mDNS %s: %w", addr, err)
	}
	m.ips = localIPv4s()
	m.mu.Lock()
	m.conn = conn.(*net.UDPConn)
	m.stop = make(chan struct{})
	m.mu.Unlock()
	m.wg.Add(2)
	go m.readLoop()
	go m.announceLoop()
	return nil
}

// Stop shuts the announcer down; safe to call when Start failed or twice.
func (m *Registrar) Stop() {
	m.mu.Lock()
	conn := m.conn
	m.conn = nil
	m.mu.Unlock()
	if conn == nil {
		return
	}
	close(m.stop)
	_ = conn.Close()
	m.wg.Wait()
}

// announceLoop sends the startup announcement burst; spaced repeats survive
// a busy LAN at boot (RFC 6762 §8.1).
func (m *Registrar) announceLoop() {
	defer m.wg.Done()
	for i := 0; i < announceBursts; i++ {
		if i > 0 {
			select {
			case <-m.stop:
				return
			case <-time.After(time.Second):
			}
		}
		m.mu.Lock()
		conn := m.conn
		m.mu.Unlock()
		if conn == nil {
			return
		}
		if msg, err := m.response(nil, 0); err == nil {
			if buf, err := msg.Pack(); err == nil {
				_, _ = conn.WriteToUDP(buf, &net.UDPAddr{IP: net.ParseIP(mdnsGroupV4), Port: mdnsPort})
			}
		}
	}
}

func (m *Registrar) readLoop() {
	defer m.wg.Done()
	buf := make([]byte, mdnsReadBuf)
	for {
		m.mu.Lock()
		conn := m.conn
		m.mu.Unlock()
		if conn == nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(mdnsDeadline))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		var query dnsmessage.Message
		if err := query.Unpack(buf[:n]); err != nil {
			continue
		}
		// Never answer responses (including our own announcements echoed
		// back by the kernel) — only questions.
		if query.Response || len(query.Questions) == 0 {
			continue
		}
		var resp *dnsmessage.Message
		// Ordinary mDNS query (source port 5353): answer multicast. Anything
		// else is a legacy one-shot query: answer unicast to the source with
		// its transaction ID (RFC 6762 §6.7).
		resp, aerr := m.answer(&query)
		if aerr != nil || resp == nil {
			continue
		}
		var dst *net.UDPAddr
		id := uint16(0)
		if src.Port != mdnsPort {
			dst = src
			id = query.ID
		} else {
			dst = &net.UDPAddr{IP: net.ParseIP(mdnsGroupV4), Port: mdnsPort}
		}
		resp.ID = id
		bufOut, err := resp.Pack()
		if err != nil {
			continue
		}
		m.mu.Lock()
		wconn := m.conn
		m.mu.Unlock()
		if wconn == nil {
			return
		}
		_, _ = wconn.WriteToUDP(bufOut, dst)
	}
}

// answer builds the response for one query; it returns (nil, nil) when the
// query holds no matching question, or when a multicast query already carries
// our records as known answers (RFC 6762 §7.1 — answering again would spark
// an answer storm between every instance seeing every other's cache).
func (m *Registrar) answer(query *dnsmessage.Message) (*dnsmessage.Message, error) {
	if query.Response {
		return nil, nil
	}
	matched := false
	for _, q := range query.Questions {
		if q.Class != dnsmessage.ClassINET && q.Class != dnsmessage.ClassANY {
			continue
		}
		name := nameString(q.Name)
		switch q.Type {
		case dnsmessage.TypePTR:
			if name == m.serviceFQDN || name == ServiceType+".local." {
				matched = true
			}
		case dnsmessage.TypeSRV, dnsmessage.TypeTXT:
			if name == m.instanceFQDN {
				matched = true
			}
		case dnsmessage.TypeA:
			if name == m.hostFQDN {
				matched = true
			}
		}
		if matched {
			break
		}
	}
	if !matched {
		return nil, nil
	}
	// Known-answer suppression: a multicast query that already lists our
	// instance's records knows about us; stay silent.
	if m.queryHasOurRecords(query) {
		return nil, nil
	}
	return m.response(query.Questions, uint16(0))
}

// response builds a full authoritative answer carrying every record a
// resolver needs to reach the API (PTR for browse, SRV+TXT for resolve, A
// for connect). The query's questions are echoed for legacy one-shot
// responses (RFC 6762 §6.7 asks the question be restated; harmless for
// multicast where questions are usually omitted).
func (m *Registrar) response(questions []dnsmessage.Question, _ uint16) (*dnsmessage.Message, error) {
	ptr := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsN(m.serviceFQDN),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
			TTL:   mdnsTTLPtr,
		},
		Body: &dnsmessage.PTRResource{PTR: dnsN(m.instanceFQDN)},
	}
	srv := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsN(m.instanceFQDN),
			Type:  dnsmessage.TypeSRV,
			Class: dnsmessage.ClassINET,
			TTL:   mdnsTTLRec,
		},
		Body: &dnsmessage.SRVResource{
			Priority: 0,
			Weight:   0,
			Port:     uint16(m.port),
			Target:   dnsN(m.hostFQDN),
		},
	}
	txt := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsN(m.instanceFQDN),
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
			TTL:   mdnsTTLRec,
		},
		Body: &dnsmessage.TXTResource{TXT: m.txt},
	}
	answers := []dnsmessage.Resource{ptr, srv, txt}
	for _, ip := range m.ips {
		a := ip.To4()
		if a == nil {
			continue
		}
		var ip4 [4]byte
		copy(ip4[:], a)
		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsN(m.hostFQDN),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   mdnsTTLRec,
			},
			Body: &dnsmessage.AResource{A: ip4},
		})
	}
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
			RCode:         dnsmessage.RCodeSuccess,
		},
		Questions: questions,
		Answers:   answers,
	}, nil
}

// queryHasOurRecords reports whether the query's answer (known-answer) section
// already carries our instance PTR/SRV/TXT.
func (m *Registrar) queryHasOurRecords(query *dnsmessage.Message) bool {
	for _, r := range query.Answers {
		switch r.Header.Type {
		case dnsmessage.TypePTR:
			if ptr, ok := r.Body.(*dnsmessage.PTRResource); ok && nameString(ptr.PTR) == m.instanceFQDN {
				return true
			}
		case dnsmessage.TypeSRV, dnsmessage.TypeTXT:
			if nameString(r.Header.Name) == m.instanceFQDN {
				return true
			}
		}
	}
	return false
}

// nameString renders a dnsmessage.Name into its canonical dotted string.
func nameString(n dnsmessage.Name) string {
	if int(n.Length) > len(n.Data) {
		return ""
	}
	return string(n.Data[:n.Length])
}

// dnsN builds a dnsmessage.Name from a dotted FQDN (must fit one label
// length budget of 255; our names are short and static).
func dnsN(s string) dnsmessage.Name {
	n, err := dnsmessage.NewName(s)
	if err != nil {
		// Our FQDNs are built from bounded inputs (service type constant +
		// trimmed instance name ≤63 chars at the call site); this branch is
		// unreachable in practice, and an empty name fails loudly on the
		// wire instead of silently announcing garbage.
		return dnsmessage.Name{}
	}
	return n
}

// dnsName builds a dnsmessage-compatible FQDN ("foo.bar." with trailing dot).
func dnsName(s string) string {
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return strings.ToLower(s)
}

// localIPv4s collects this host's unicast IPv4 addresses (all up,
// non-loopback interfaces) for the A records — the client picks whichever it
// can reach, which is what a multi-homed box (eth+wifi) needs.
func localIPv4s() []net.IP {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipn, ok := addr.(*net.IPNet); ok {
				if ip := ipn.IP.To4(); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips
}

func osHostname() (string, error) {
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "steward", nil
	}
	return strings.TrimSpace(h), nil
}
