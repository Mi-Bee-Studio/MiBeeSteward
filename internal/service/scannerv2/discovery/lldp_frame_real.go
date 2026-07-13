//go:build WITH_LLDP

// Real build (WITH_LLDP): a passive LLDPDU frame listener. Captures ethertype
// 0x88cc frames via AF_PACKET raw sockets (requires CAP_NET_RAW) and parses the
// TLV chain into neighbor edges. This is the only way to see LLDP-broadcasting
// endpoints (IP phones, APs, NAS) that don't run SNMP LLDP-MIB — the SNMP
// LLDP-MIB probe (active:lldp_mib) only sees managed switches.
//
// Default builds ship the stub (lldp_frame_stub.go); build with -tags WITH_LLDP
// to enable. This mirrors the eBPF observer's build-tag pattern: the default
// build stays unprivileged.

package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// lldpEdge is defined in lldp_types.go (shared across build variants).

// lldpFrameSource passively listens for LLDPDU broadcasts on one or more NICs.
// On each frame it parses the TLV chain and (a) emits a NewHostEvent for the
// remote chassis (host discovery) and (b) pushes a neighbor edge via the
// neighborSink closure (topology). Both outputs use the same parsed data.
type lldpFrameSource struct {
	interfaces   []string
	svc          *Service
	neighborSink func(localMAC string, neighbors []lldpEdge)
	logger       *slog.Logger
	ifaceMACs    map[string]string // iface name → local MAC (for LocalMAC)
}

// NewLLDPFrameSource constructs the listener. interfaces is the list of NIC
// names to listen on (empty = all non-loopback UP interfaces). svc is the
// discovery coordinator (host events); neighborSink receives neighbor edges.
func NewLLDPFrameSource(interfaces []string, svc *Service, neighborSink func(localMAC string, neighbors []lldpEdge), logger *slog.Logger) *lldpFrameSource {
	if logger == nil {
		logger = slog.Default()
	}
	if len(interfaces) == 0 {
		interfaces = allUpInterfaces(logger)
	}
	if len(interfaces) == 0 {
		logger.Warn("lldp_frame: no interfaces to listen on; source disabled")
		return nil
	}
	macs := make(map[string]string, len(interfaces))
	for _, name := range interfaces {
		if mac, err := ifaceMAC(name); err == nil && mac != "" {
			macs[name] = mac
		}
	}
	return &lldpFrameSource{
		interfaces:   interfaces,
		svc:          svc,
		neighborSink: neighborSink,
		logger:       logger,
		ifaceMACs:    macs,
	}
}

func (s *lldpFrameSource) Name() string { return "lldp_frame" }

// Start opens one AF_PACKET raw socket per interface (ethertype 0x88cc) and
// reads LLDPDUs until ctx is cancelled. Blocking; run in its own goroutine.
func (s *lldpFrameSource) Start(ctx context.Context) {
	var wg sync.WaitGroup
	for _, name := range s.interfaces {
		wg.Add(1)
		go func(iface string) {
			defer wg.Done()
			s.listen(ctx, iface)
		}(name)
	}
	wg.Wait()
}

func (s *lldpFrameSource) listen(ctx context.Context, iface string) {
	sock, err := openLLDPSocket(iface)
	if err != nil {
		s.logger.Warn("lldp_frame: open socket failed", "iface", iface, "error", err)
		return
	}
	defer syscall.Close(sock)
	s.logger.Info("lldp_frame: listening", "iface", iface)

	buf := make([]byte, 65536)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		// Set a read deadline so the ctx-cancel check fires promptly even with
		// no traffic.
		_ = syscall.SetsockoptTimeval(sock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
			&syscall.Timeval{Sec: 1, Usec: 0})
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
				continue
			}
			s.logger.Debug("lldp_frame: read error", "iface", iface, "error", err)
			continue
		}
		if n < 14 { // too small for an Ethernet header
			continue
		}
		frame := buf[:n]
		// Ethernet header: dst(6) src(6) ethertype(2). Verify ethertype 0x88cc.
		et := binary.BigEndian.Uint16(frame[12:14])
		if et != 0x88cc {
			continue
		}
		srcMAC := net.HardwareAddr(frame[6:12]).String()
		lldpdu := frame[14:]
		edge := parseLLDPDU(lldpdu, srcMAC, iface, s.ifaceMACs[iface])
		if edge.NeighborMAC == "" {
			continue // no subtype-4 chassis id — can't merge
		}
		// (a) host discovery — the chassis is a host on this network.
		if s.svc != nil {
			s.svc.Emit(NewHostEvent{IP: "", MAC: edge.NeighborMAC, Source: "lldp_frame"})
		}
		// (b) neighbor edge — local interface sees this neighbor.
		if s.neighborSink != nil {
			s.neighborSink(s.ifaceMACs[iface], []lldpEdge{edge})
		}
	}
}

// parseLLDPDU walks the TLV chain (IEEE 802.1AB). Each TLV: 7-bit type | 9-bit
// length, then length bytes of payload. Type 0 (End of LLDPDU) terminates.
// Extracts: Chassis ID (type 1, subtype 4 = MAC), Port ID (type 2, the remote
// port identifier). The srcMAC from the Ethernet header is the fallback when
// the chassis id isn't a MAC subtype.
func parseLLDPDU(data []byte, srcMAC, iface, localMAC string) lldpEdge {
	edge := lldpEdge{Protocol: "LLDP", NeighborMAC: srcMAC, LocalMAC: localMAC, LocalPort: iface}
	for i := 0; i+1 < len(data); {
		tlv := uint16(data[i])<<8 | uint16(data[i+1])
		t := tlv >> 9
		l := int(tlv & 0x1FF)
		i += 2
		if i+l > len(data) {
			break // truncated TLV
		}
		payload := data[i : i+l]
		i += l
		switch t {
		case 0: // End of LLDPDU
			return edge
		case 1: // Chassis ID — first byte is subtype; subtype 4 = MAC (6 octets)
			if len(payload) >= 1 && payload[0] == 4 && len(payload) == 7 {
				edge.NeighborMAC = net.HardwareAddr(payload[1:7]).String()
			}
		case 2: // Port ID — first byte is subtype; the rest is the port identifier
			if len(payload) > 1 {
				edge.RemotePort = string(payload[1:])
			}
		}
	}
	return edge
}

// openLLDPSocket opens an AF_PACKET raw socket bound to iface for ethertype
// 0x88cc (LLDP). Requires CAP_NET_RAW.
func openLLDPSocket(iface string) (int, error) {
	// AF_PACKET protocol is a network-byte-order uint16 passed as int.
	proto := int(htons(0x88cc))
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		return 0, fmt.Errorf("socket: %w", err)
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		syscall.Close(sock)
		return 0, fmt.Errorf("interface %s: %w", iface, err)
	}
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(0x88cc),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		syscall.Close(sock)
		return 0, fmt.Errorf("bind: %w", err)
	}
	return sock, nil
}

// htons converts a uint16 to network byte order (AF_PACKET protocols are passed
// in network order on Linux).
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// allUpInterfaces returns the names of all non-loopback, UP interfaces.
func allUpInterfaces(logger *slog.Logger) []string {
	ifs, err := net.Interfaces()
	if err != nil {
		logger.Warn("lldp_frame: enumerate interfaces failed", "error", err)
		return nil
	}
	var out []string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, ifi.Name)
	}
	return out
}

// ifaceMAC returns the hardware address of an interface as a canonical string.
func ifaceMAC(name string) (string, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	if ifi.HardwareAddr == nil {
		return "", nil
	}
	return ifi.HardwareAddr.String(), nil
}

// time import kept for future read-deadline variants; harmless.
var _ = time.Second
