// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// reuseJoinControl is a ListenConfig.Control that sets SO_REUSEADDR AND joins
// the multicast group via IP_ADD_MEMBERSHIP. SO_REUSEADDR lets the listener bind
// alongside a system resolver (avahi, systemd-resolved) that already holds
// :5353 / :1900; it deliberately does NOT set SO_REUSEPORT (that would split
// incoming datagrams between us and the resolver, halving both our coverage).
//
// The IP_ADD_MEMBERSHIP is the critical part that was missing before: binding to
// a multicast address (or to 0.0.0.0:port) does NOT by itself cause the kernel
// to deliver multicast packets to the socket. The kernel only forwards packets
// sent to a group to sockets that have explicitly joined that group. Without the
// join, the listener opens successfully and the read loop runs forever — but
// receives nothing, because the kernel never hands it any multicast traffic.
// This was the root cause of the multicast source emitting zero events despite
// devices broadcasting on the link.
//
// ifaceName selects the interface to join on (empty = the first up,
// multicast-capable, non-loopback interface, which is the common single-NIC
// case). Joining on a specific interface is required for IP_ADD_MEMBERSHIP to
// receive link-local multicast (224.0.0.251) — the kernel needs to know which
// L2 segment to listen on.
func reuseJoinControl(group, ifaceName string) func(network, address string, c syscall.RawConn) error {
	ifi, ifiErr := multicastInterface(ifaceName)
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if sockErr != nil {
				return
			}
			if ifiErr != nil {
				sockErr = ifiErr
				return
			}
			mreq := syscall.IPMreq{}
			copy(mreq.Multiaddr[:], net.ParseIP(group).To4())
			// Bind membership to the interface's IPv4 address (INADDR_ANY +
			// imr_interface = kernel picks the default-route iface, but pinning
			// it makes the choice deterministic and works when there is no
			// default route, e.g. on a host with only a link-local config).
			if ifi != nil && len(ifi.Addr) >= 4 {
				copy(mreq.Interface[:], ifi.Addr[:4])
			}
			sockErr = syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP,
				syscall.IP_ADD_MEMBERSHIP, &mreq)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

// multicastInterface resolves the interface to join multicast groups on. When
// name is non-empty it must name an up, multicast-capable interface; otherwise
// the first up, multicast-capable, non-loopback interface with an IPv4 address
// is used (skips lo, docker0, etc.). Returns the interface with its primary IPv4
// address in a small struct so the caller can pin IP_ADD_MEMBERSHIP to it.
func multicastInterface(name string) (*ipv4If, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// Named interface: resolve and validate, but don't fall through to auto.
	if name != "" {
		for _, ifi := range ifis {
			if ifi.Name != name {
				continue
			}
			return ipv4FromInterface(ifi)
		}
		return nil, fmt.Errorf("interface %q not found", name)
	}
	// Auto: first up + multicast + non-loopback with an IPv4 address.
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if v4 := ipv4FromInterfaceOrNil(ifi); v4 != nil {
			return v4, nil
		}
	}
	return nil, errors.New("no up, multicast-capable, non-loopback interface with an IPv4 address")
}

// ipv4If carries an interface index plus its primary IPv4 address, used to pin
// an IP_ADD_MEMBERSHIP request to a specific interface.
type ipv4If struct {
	Index int
	Addr  net.IP
}

func ipv4FromInterface(ifi net.Interface) (*ipv4If, error) {
	v4 := ipv4FromInterfaceOrNil(ifi)
	if v4 == nil {
		return nil, fmt.Errorf("interface %q has no IPv4 address", ifi.Name)
	}
	return v4, nil
}

func ipv4FromInterfaceOrNil(ifi net.Interface) *ipv4If {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return &ipv4If{Index: ifi.Index, Addr: ip4}
		}
	}
	return nil
}

// MulticastSource passively listens for mDNS (224.0.0.251:5353) and SSDP
// (239.255.255.250:1900) traffic WITHOUT sending any queries. Hosts that
// self-advertise — cameras (ONVIF/RTSP), printers, IoT gadgets, Macs (Bonjour),
// UPnP/DLNA devices — surface here as a byproduct of their normal background
// chatter, so this source costs zero outbound traffic.
//
// It is a supplemental source: only hosts that actively broadcast are seen, so
// it doesn't replace the router-ARP sweep. But it carries richer hints than a
// bare MAC — an _onvif._tcp service strongly implies a camera — which the
// coordinator folds into the synthesized report as device-type hints.
//
// The listener binds with SO_REUSEADDR so it coexists with avahi/
// systemd-resolved when they already hold the port; if the bind fails entirely
// (e.g. no multicast-capable interface, or a stricter socket filter) the source
// logs a warning and disables itself rather than crashing the service.
type MulticastSource struct {
	svc    *Service
	logger *slog.Logger

	started atomic.Bool
	done    chan struct{}
}

// NewMulticastSource constructs the source.
func NewMulticastSource(svc *Service, logger *slog.Logger) *MulticastSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &MulticastSource{svc: svc, logger: logger}
}

// Start opens both multicast sockets and reads from them until ctx is cancelled.
// If a socket can't be opened (port busy + no SO_REUSEADDR, or no multicast
// route), that protocol is skipped with a warning; the other may still come up.
// Idempotent: a second Start is a no-op.
func (s *MulticastSource) Start(ctx context.Context) {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	s.done = make(chan struct{})
	go s.run(ctx)
}

// Done returns a channel closed when the read loop exits (ctx cancelled or both
// sockets errored out). Allows the caller to know the source has wound down.
func (s *MulticastSource) Done() <-chan struct{} { return s.done }

func (s *MulticastSource) run(ctx context.Context) {
	defer close(s.done)

	var wg sync.WaitGroup
	for _, m := range []multicastListener{
		newMDNSListener(s.svc, s.logger),
		newSSDPListener(s.svc, s.logger),
	} {
		conn, err := m.listen()
		if err != nil {
			s.logger.Warn("discovery: multicast source disabled",
				"proto", m.proto, "error", err)
			continue
		}
		wg.Add(1)
		go func(c net.PacketConn, ml multicastListener) {
			defer wg.Done()
			defer c.Close()
			ml.readLoop(ctx, c)
		}(conn, m)
	}
	wg.Wait()
}

// multicastListener describes one passive multicast listener (mDNS or SSDP).
type multicastListener interface {
	proto() string
	listen() (net.PacketConn, error)
	readLoop(ctx context.Context, conn net.PacketConn)
}

// --- mDNS (224.0.0.251:5353) ---

const (
	// mDNS/SSDP multicast group IPs and ports. The listeners bind 0.0.0.0:port
	// (so the kernel routes multicast packets to them once they JOIN the group)
	// rather than the group address itself — binding the group address does not
	// imply group membership and yields zero delivered packets (see
	// reuseJoinControl). These group IPs are passed to IP_ADD_MEMBERSHIP.
	mdnsGroupIP = "224.0.0.251"
	mdnsPort    = "5353"
	ssdpGroupIP = "239.255.255.250"
	ssdpPort    = "1900"
	readBuf     = 65536
)

type mdnsListener struct {
	svc    *Service
	logger *slog.Logger
}

func newMDNSListener(svc *Service, logger *slog.Logger) multicastListener {
	return &mdnsListener{svc: svc, logger: logger}
}

func (m *mdnsListener) proto() string { return "mdns" }

func (m *mdnsListener) listen() (net.PacketConn, error) {
	// Bind 0.0.0.0:5353 and JOIN the 224.0.0.251 group. The join is what makes
	// the kernel deliver mDNS multicast to us — see reuseJoinControl. SO_REUSEADDR
	// lets us coexist with avahi/systemd-resolved; we do NOT use SO_REUSEPORT
	// (that would split datagrams between us and the resolver).
	lc := net.ListenConfig{
		Control: reuseJoinControl(mdnsGroupIP, ""),
	}
	conn, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:"+mdnsPort)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *mdnsListener) readLoop(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, readBuf)
	for {
		if ctx.Err() != nil {
			return
		}
		// Set a read deadline so the loop can observe ctx cancellation even when
		// no packets arrive.
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne := (net.Error)(nil); errors.As(err, &ne) && ne.Timeout() {
				continue // expected: deadline-driven wake to re-check ctx
			}
			m.logger.Debug("discovery: mdns read error", "error", err)
			continue
		}
		ip := srcIP(addr)
		if ip == "" {
			continue
		}
		hints := parseMDNSHints(buf[:n])
		m.svc.Emit(NewHostEvent{IP: ip, Source: "mdns", Hints: hints})
	}
}

// parseMDNSHints pulls service-type clues out of an mDNS packet for use as
// device-type hints. It's a deliberately shallow scan (no full DNS parsing): it
// looks for well-known service labels in the raw bytes and maps them to hint
// keys the coordinator folds into the device fields. Returns nil when nothing
// recognizable is present.
func parseMDNSHints(pkt []byte) map[string]string {
	s := string(pkt)
	var hints map[string]string
	add := func(k, v string) {
		if hints == nil {
			hints = map[string]string{}
		}
		hints[k] = v
	}
	// These service types are byte-stable labels inside the DNS packet, so a
	// substring search is reliable enough for a hint (never an identity).
	switch {
	case strings.Contains(s, "_onvif._tcp"):
		add("inferred_type", "camera")
		add("discovery_note", "onvif")
	case strings.Contains(s, "_rtsp._tcp"):
		add("inferred_type", "camera")
		add("discovery_note", "rtsp")
	case strings.Contains(s, "_ipp._tcp"), strings.Contains(s, "_printer._tcp"):
		add("inferred_type", "printer")
	case strings.Contains(s, "_airplay._tcp"):
		add("inferred_type", "appletv")
	case strings.Contains(s, "_googlecast._tcp"):
		add("inferred_type", "chromecast")
	case strings.Contains(s, "_smb._tcp"):
		add("inferred_type", "nas")
	case strings.Contains(s, "_ssh._tcp"):
		add("inferred_type", "server")
	}
	return hints
}

// --- SSDP (239.255.255.250:1900) ---

type ssdpListener struct {
	svc    *Service
	logger *slog.Logger
}

func newSSDPListener(svc *Service, logger *slog.Logger) multicastListener {
	return &ssdpListener{svc: svc, logger: logger}
}

func (s *ssdpListener) proto() string { return "ssdp" }

func (s *ssdpListener) listen() (net.PacketConn, error) {
	// Bind 0.0.0.0:1900 and JOIN the 239.255.255.250 group (UPnP/SSDP). Same
	// rationale as the mDNS listener: the join is what delivers multicast.
	lc := net.ListenConfig{
		Control: reuseJoinControl(ssdpGroupIP, ""),
	}
	conn, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:"+ssdpPort)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *ssdpListener) readLoop(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, readBuf)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne := (net.Error)(nil); errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.logger.Debug("discovery: ssdp read error", "error", err)
			continue
		}
		ip := srcIP(addr)
		if ip == "" {
			continue
		}
		hints := parseSSDPHints(buf[:n])
		s.svc.Emit(NewHostEvent{IP: ip, Source: "ssdp", Hints: hints})
	}
}

// parseSSDPHints extracts device-type clues from an SSDP NOTIFY/SEARCH reply.
// SSDP is HTTP-like text, so we scan for the SERVER/ST/NT lines that carry the
// device class (e.g. "urn:schemas-upnp-org:device:MediaRenderer").
func parseSSDPHints(pkt []byte) map[string]string {
	s := string(pkt)
	var hints map[string]string
	add := func(k, v string) {
		if hints == nil {
			hints = map[string]string{}
		}
		hints[k] = v
	}
	switch {
	case strings.Contains(s, "MediaRenderer"), strings.Contains(s, "DigitalMediaRenderer"):
		add("inferred_type", "mediarenderer")
	case strings.Contains(s, "MediaServer"):
		add("inferred_type", "mediaserver")
	case strings.Contains(s, "InternetGatewayDevice"):
		add("inferred_type", "router")
	case strings.Contains(s, "Printer"):
		add("inferred_type", "printer")
	case strings.Contains(s, "Basic"):
		add("discovery_note", "ssdp-basic")
	}
	return hints
}

// srcIP extracts the sender's IPv4 from a ReadFrom address.
func srcIP(addr net.Addr) string {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return ""
	}
	ap := netip.AddrPortFrom(netip.AddrFrom4([4]byte(udp.IP.To4())), 0)
	if !ap.IsValid() {
		return ""
	}
	return ap.Addr().String()
}
