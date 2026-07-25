// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

//go:build WITH_ARPSCAN

// ARPScanSource actively discovers every host on the local subnet by sending ARP
// "who-has" requests for each IP and collecting the replies. Unlike the ICMP ping
// sweep (which firewalls can silently drop) or the passive arp_cache source (which
// only sees hosts the scanner has already talked to), an ARP request is a L2
// broadcast that every host on the segment MUST answer — it is the most complete
// single-host, no-router-access discovery available.
//
// It uses one AF_PACKET raw socket (CAP_NET_RAW) per sweep: send N who-has frames,
// then read replies for a short window. Coverage is the local broadcast domain
// only (ARP is not routed); cross-subnet discovery remains the agent's job.
//
// Default builds ship the stub (arp_scan_stub.go); build with -tags WITH_ARPSCAN
// to enable. Mirrors the LLDP/CDP frame sources' build-tag pattern.

package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"
)

// ethTypeARP is the EtherType for ARP (0x0806).
const ethTypeARP = 0x0806

// arpOpRequest / arpOpReply are the ARP opcode values.
const (
	arpOpRequest = 1
	arpOpReply   = 2
)

// ARPScanSource periodically sweeps the local subnet with ARP requests and emits
// a NewHostEvent for each responder's IP+MAC.
type ARPScanSource struct {
	cidr     string        // subnet to sweep, e.g. "192.168.63.0/24"
	iface    string        // interface to send on (empty = derive from cidr)
	srcMAC   [6]byte       // sender hardware address (our NIC)
	srcIP    [4]byte       // sender protocol address (our NIC's IPv4)
	interval time.Duration // sweep cadence
	ifindex  int           // interface index for sockaddr_ll
	svc      *Service
	logger   *slog.Logger

	mu       sync.Mutex
	previous map[string]string // ip → mac, last sweep (diff base)
}

// NewARPScanSource constructs the source. cidr is the subnet to sweep; iface is
// the interface to send/receive on (empty = auto-select the interface whose IPv4
// address falls inside cidr). Returns nil with a warning log when the socket
// can't be opened (no CAP_NET_RAW) or no suitable interface is found — callers
// must nil-check (the routes.go wiring guards on a non-nil return).
func NewARPScanSource(cidr string, interval time.Duration, iface string, svc *Service, logger *slog.Logger) *ARPScanSource {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	src := &ARPScanSource{
		cidr:     cidr,
		iface:    iface,
		interval: interval,
		svc:      svc,
		logger:   logger,
		previous: map[string]string{},
	}
	if err := src.resolveInterface(); err != nil {
		// Distinguish "not root / no raw socket" (expected on many hosts) from a
		// genuine misconfiguration. Both are non-fatal: the source is skipped, and
		// the rest of discovery keeps running.
		logger.Warn("discovery: arp_scan source disabled",
			"cidr", cidr, "iface", iface, "error", err,
			"hint", "requires CAP_NET_RAW (run as root or grant the capability)")
		return nil
	}
	return src
}

// resolveInterface picks the sending interface + MAC + IP. When iface is set it
// must name an up interface with an IPv4 in cidr; otherwise the first up,
// non-loopback interface whose IPv4 falls inside cidr is used. It also probes an
// AF_PACKET socket to confirm CAP_NET_RAW is available (the source can't function
// without it). Failing any check returns an error so the constructor returns nil.
func (s *ARPScanSource) resolveInterface() error {
	_, ipnet, err := net.ParseCIDR(s.cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", s.cidr, err)
	}

	pick := func(name string) error {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		if ifi.Flags&net.FlagUp == 0 {
			return fmt.Errorf("interface %s is down", name)
		}
		hw := ifi.HardwareAddr
		if len(hw) != 6 {
			return fmt.Errorf("interface %s has non-Ethernet MAC (%d bytes)", name, len(hw))
		}
		ip, _, ok := ifaceIPv4(name)
		if !ok {
			return fmt.Errorf("interface %s has no IPv4 address", name)
		}
		if !ipnet.Contains(ip) {
			return fmt.Errorf("interface %s IPv4 %s not in cidr %s", name, ip, s.cidr)
		}
		copy(s.srcMAC[:], hw)
		copy(s.srcIP[:], ip.To4())
		s.ifindex = ifi.Index
		s.iface = name
		return nil
	}

	if s.iface != "" {
		if err := pick(s.iface); err != nil {
			return err
		}
	} else {
		// Auto-select: first up, non-loopback interface with an IPv4 inside cidr.
		names := allUpInterfaces(s.logger)
		found := false
		for _, n := range names {
			if err := pick(n); err == nil {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no up interface with an IPv4 in cidr %s", s.cidr)
		}
	}

	// Confirm we can actually open an AF_PACKET socket before declaring success.
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethTypeARP)))
	if err != nil {
		return fmt.Errorf("open raw socket (need CAP_NET_RAW): %w", err)
	}
	syscall.Close(sock)
	return nil
}

// Start launches the sweep goroutine (immediate first sweep, then ticks).
func (s *ARPScanSource) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *ARPScanSource) loop(ctx context.Context) {
	s.sweep(ctx)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep(ctx)
		}
	}
}

// sweep opens a raw socket, broadcasts a who-has for every host IP in cidr, then
// collects replies for a short window. Each newly-seen IP (vs the previous sweep)
// is emitted as a NewHostEvent. The socket is opened per sweep (not held open for
// the whole lifetime) so the source survives interface/MAC changes across reboots
// without a restart, and a single failed sweep doesn't poison the socket forever.
func (s *ARPScanSource) sweep(ctx context.Context) {
	sock, err := openARPScanSocket(s.ifindex)
	if err != nil {
		// Warn, not Debug: a socket failure means the source is silently blind
		// (every sweep no-ops), which is exactly the "0 events, no log" trap we
		// hit before. CAP_NET_RAW missing or dropped by the sandbox is the usual
		// cause and is actionable.
		s.logger.Warn("discovery: arp_scan socket open failed", "iface", s.iface, "error", err,
			"hint", "requires CAP_NET_RAW (ambient capability or root)")
		return
	}
	defer syscall.Close(sock)

	// Resolve the full host list (exclude network + broadcast) once per sweep.
	ips := subnetHostIPs(s.cidr)
	if len(ips) == 0 {
		return
	}

	// Broadcast all who-has requests as fast as the socket accepts them. We don't
	// wait between sends: ARP replies arrive asynchronously and we collect them in
	// the read window below. A /24 (254 hosts) is a few KB of traffic — negligible.
	template := buildARPRequest(s.srcMAC, s.srcIP)
	bcast := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	sent := 0
	for _, ip := range ips {
		var tgt [4]byte
		copy(tgt[:], ip.To4())
		frame := fillARPRequestTarget(template, bcast, s.srcMAC, s.srcIP, tgt)
		if err := sendARPL2(sock, s.ifindex, frame); err == nil {
			sent++
		}
	}

	// Collect replies for a short window. Most hosts reply within tens of ms; we
	// allow up to replyWindow to catch slow/loaded responders. The deadline is
	// re-set per read so ctx cancellation is observed between packets.
	const replyWindow = 1500 * time.Millisecond
	deadline := time.Now().Add(replyWindow)
	current := map[string]string{}
	buf := make([]byte, 128) // 14 (eth) + 28 (arp) is enough; pad for VLAN tags
	recvPackets := 0
	for {
		if ctx.Err() != nil {
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		_ = syscall.SetsockoptTimeval(sock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
			&syscall.Timeval{Sec: int64(remaining / time.Second), Usec: int64(remaining.Microseconds()) % 1e6})
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK) {
				continue // timeout slice exhausted; loop re-checks the deadline
			}
			continue
		}
		recvPackets++
		if ip, mac, ok := parseARPReply(buf[:n]); ok {
			current[ip] = mac
		}
	}

	s.logger.Info("discovery: arp_scan sweep done",
		"iface", s.iface, "sent", sent, "targets", len(ips),
		"recv_packets", recvPackets, "replies", len(current))

	if len(current) == 0 {
		return
	}

	s.mu.Lock()
	prev := s.previous
	s.previous = current
	s.mu.Unlock()

	for ip, mac := range current {
		if _, wasPresent := prev[ip]; wasPresent {
			continue
		}
		s.svc.Emit(NewHostEvent{IP: ip, MAC: mac, Source: "arp_scan"})
	}
}

// openARPScanSocket opens an AF_PACKET raw socket bound to ifindex for ARP
// (ethertype 0x0806). Requires CAP_NET_RAW.
func openARPScanSocket(ifindex int) (int, error) {
	proto := int(htons(ethTypeARP))
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		return 0, fmt.Errorf("socket: %w", err)
	}
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(ethTypeARP),
		Ifindex:  ifindex,
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		syscall.Close(sock)
		return 0, fmt.Errorf("bind: %w", err)
	}
	return sock, nil
}

// sendARPL2 writes a raw Ethernet frame via the bound AF_PACKET socket using a
// sockaddr_ll carrying the destination MAC. The frame already includes its own
// Ethernet header; sockaddr_ll's Halen/Haddr is how the kernel knows the L2 next
// hop for SOCK_RAW (the packet is NOT re-encapsulated).
func sendARPL2(sock, ifindex int, frame []byte) error {
	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(ethTypeARP),
		Ifindex:  ifindex,
		Halen:    6,
	}
	copy(sll.Addr[:], frame[0:6]) // dst MAC = frame's Ethernet destination
	return syscall.Sendto(sock, frame, 0, sll)
}

// buildARPRequest returns a reusable 42-byte Ethernet+ARP who-has frame with a
// zeroed target IP/MAC — callers copy it and fill the per-IP target via
// fillARPRequestTarget. Allocating once and copying per-IP avoids 254 separate
// heap allocations per sweep.
//
// Layout (EthernetII + Ethernet/IPv4 ARP):
//
//	[0..5]   dst MAC  (filled per-target: broadcast for requests)
//	[6..11]  src MAC  (our NIC)
//	[12..13] ethertype 0x0806 (ARP)
//	[14..15] htype 1 (Ethernet)
//	[16..17] ptype 0x0800 (IPv4)
//	[18]     hlen 6
//	[19]     plen 4
//	[20..21] op 1 (request)
//	[22..27] sender HW addr (our MAC)
//	[28..31] sender proto addr (our IP)
//	[32..37] target HW addr (0 — unknown, that's what we're asking)
//	[38..41] target proto addr (filled per-target)
func buildARPRequest(srcMAC [6]byte, srcIP [4]byte) []byte {
	f := make([]byte, 42)
	// dst left zero — set per-target by fillARPRequestTarget
	copy(f[6:12], srcMAC[:])
	f[12] = 0x08
	f[13] = 0x06 // ethertype ARP
	f[14] = 0x00
	f[15] = 0x01 // htype Ethernet
	f[16] = 0x08
	f[17] = 0x00 // ptype IPv4
	f[18] = 6    // hlen
	f[19] = 4    // plen
	f[20] = 0x00
	f[21] = arpOpRequest // op request
	copy(f[22:28], srcMAC[:])
	copy(f[28:32], srcIP[:])
	// [32..37] target HW addr stays zero
	// [38..41] target proto addr set per-target
	return f
}

// fillARPRequestTarget copies the template frame, sets the Ethernet destination
// and ARP target IP, and returns the ready-to-send frame.
func fillARPRequestTarget(template []byte, dstMAC, srcMAC [6]byte, srcIP, tgtIP [4]byte) []byte {
	f := make([]byte, len(template))
	copy(f, template)
	copy(f[0:6], dstMAC[:])
	copy(f[6:12], srcMAC[:])
	copy(f[28:32], srcIP[:])
	copy(f[38:42], tgtIP[:])
	return f
}

// parseARPReply extracts the sender IP+MAC from an inbound EthernetII ARP frame.
// Returns ok=false for anything that isn't an ARP reply (wrong ethertype, wrong
// opcode, truncated, VLAN-tagged-but-unparseable, etc.).
func parseARPReply(frame []byte) (ip, mac string, ok bool) {
	// Minimum EthernetII + ARP frame is 42 bytes. Tolerate 802.1Q VLAN tags
	// (+4 bytes) only loosely: if ethertype isn't immediately ARP, bail.
	if len(frame) < 42 {
		return "", "", false
	}
	if frame[12] != 0x08 || frame[13] != 0x06 {
		return "", "", false // not ARP
	}
	if frame[14] != 0x00 || frame[15] != 0x01 { // htype != Ethernet
		return "", "", false
	}
	if frame[16] != 0x08 || frame[17] != 0x00 { // ptype != IPv4
		return "", "", false
	}
	op := uint16(frame[20])<<8 | uint16(frame[21])
	if op != arpOpReply {
		return "", "", false // we only learn from replies, not our own requests
	}
	mac = net.HardwareAddr(frame[22:28]).String()
	ip = net.IP(frame[28:32]).String()
	return ip, mac, true
}

// subnetHostIPs expands a CIDR into its usable host IPs (excluding the network
// and broadcast addresses). For /31 and /32 it returns the address(es) as-is
// (point-to-point / single-host conventions). Returns nil for an unparseable
// CIDR or a non-IPv4 CIDR.
func subnetHostIPs(cidr string) []net.IP {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil || ipnet.IP.To4() == nil {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil
	}
	// /31, /32: no network/broadcast carve-out (RFC 3021 / single host).
	if ones >= 31 {
		return []net.IP{ip4}
	}
	netAddr := ipnet.IP.To4()
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = netAddr[i] | ^ipnet.Mask[i]
	}
	var out []net.IP
	cur := append(net.IP(nil), netAddr...)
	inc := func(b net.IP) {
		for j := 3; j >= 0; j-- {
			b[j]++
			if b[j] != 0 {
				break
			}
		}
	}
	for inc(cur); cur4inRange(cur, netAddr, bcast); inc(cur) {
		dst := append(net.IP(nil), cur...)
		out = append(out, dst)
	}
	return out
}

// cur4inRange reports whether a 4-byte IP is strictly between netAddr (exclusive)
// and bcast (exclusive) — i.e. a usable host address.
func cur4inRange(cur, netAddr, bcast net.IP) bool {
	for i := 0; i < 4; i++ {
		if cur[i] != netAddr[i] {
			break
		}
		if i == 3 {
			return false // == network addr
		}
	}
	for i := 0; i < 4; i++ {
		if cur[i] != bcast[i] {
			break
		}
		if i == 3 {
			return false // == broadcast addr
		}
	}
	return true
}
