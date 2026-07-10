package discovery

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// reuseControl is a ListenConfig.Control that sets SO_REUSEADDR on the socket so
// the multicast listener can bind alongside a system resolver (avahi,
// systemd-resolved) that already holds :5353 / :1900. It deliberately does NOT
// set SO_REUSEPORT: that would split incoming datagrams between us and the
// system resolver, halving both our coverage. REUSEADDR alone lets us co-listen.
func reuseControl(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
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
	mdnsGroup = "224.0.0.251:5353"
	ssdpGroup = "239.255.255.250:1900"
	readBuf   = 65536
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
	// SO_REUSEADDR lets us share :5353 with avahi/systemd-resolved. We do NOT
	// set SO_REUSEPORT here because that would split datagrams between us and
	// the system resolver — REUSEADDR alone is enough to bind alongside it.
	lc := net.ListenConfig{
		Control: reuseControl,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp4", mdnsGroup)
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
	lc := net.ListenConfig{
		Control: reuseControl,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp4", ssdpGroup)
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
