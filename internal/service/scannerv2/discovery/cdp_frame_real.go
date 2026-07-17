//go:build WITH_CDP

// Real build (WITH_CDP): a passive CDP frame listener. Captures ethertype
// 0x2000 frames via AF_PACKET raw sockets (requires CAP_NET_RAW) and parses
// the TLV chain into neighbor edges. This complements the LLDP listener for
// Cisco environments where LLDP is not enabled.
//
// Default builds ship the stub (cdp_frame_stub.go); build with -tags WITH_CDP
// to enable. This mirrors the LLDP frame listener's build-tag pattern.

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
)

// CDPFrameSource passively listens for CDP broadcasts on one or more NICs.
// On each frame it parses the TLV chain and (a) emits a NewHostEvent for the
// remote device (host discovery) and (b) pushes a neighbor edge via the
// neighborSink closure (topology). Both outputs use the same parsed data.
type CDPFrameSource struct {
	interfaces   []string
	svc          *Service
	neighborSink func(localMAC string, neighbors []cdpEdge)
	logger       *slog.Logger
	ifaceMACs    map[string]string // iface name → local MAC (for LocalMAC)
}

// NewCDPFrameSource constructs the listener. interfaces is the list of NIC
// names to listen on (empty = all non-loopback UP interfaces). svc is the
// discovery coordinator (host events); neighborSink receives neighbor edges.
func NewCDPFrameSource(interfaces []string, svc *Service, neighborSink func(localMAC string, neighbors []cdpEdge), logger *slog.Logger) *CDPFrameSource {
	if logger == nil {
		logger = slog.Default()
	}
	if len(interfaces) == 0 {
		interfaces = allUpInterfaces(logger)
	}
	if len(interfaces) == 0 {
		logger.Warn("cdp_frame: no interfaces to listen on; source disabled")
		return nil
	}
	macs := make(map[string]string, len(interfaces))
	for _, name := range interfaces {
		if mac, err := ifaceMAC(name); err == nil && mac != "" {
			macs[name] = mac
		}
	}
	return &CDPFrameSource{
		interfaces:   interfaces,
		svc:          svc,
		neighborSink: neighborSink,
		logger:       logger,
		ifaceMACs:    macs,
	}
}

func (s *CDPFrameSource) Name() string { return "cdp_frame" }

// Start opens one AF_PACKET raw socket per interface (ethertype 0x2000) and
// reads CDP frames until ctx is cancelled. Blocking; run in its own goroutine.
func (s *CDPFrameSource) Start(ctx context.Context) {
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

func (s *CDPFrameSource) listen(ctx context.Context, iface string) {
	sock, err := openCDPSocket(iface)
	if err != nil {
		s.logger.Warn("cdp_frame: open socket failed", "iface", iface, "error", err)
		return
	}
	defer syscall.Close(sock)
	s.logger.Info("cdp_frame: listening", "iface", iface)

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
			s.logger.Debug("cdp_frame: read error", "iface", iface, "error", err)
			continue
		}
		if n < 14 { // too small for an Ethernet header
			continue
		}
		frame := buf[:n]
		// Ethernet header: dst(6) src(6) ethertype(2). Verify ethertype 0x2000.
		et := binary.BigEndian.Uint16(frame[12:14])
		if et != 0x2000 {
			continue
		}
		srcMAC := net.HardwareAddr(frame[6:12]).String()
		cdpData := frame[14:]
		edge := parseCDPFrame(cdpData, srcMAC, iface, s.ifaceMACs[iface])
		if edge.NeighborMAC == "" {
			continue // no valid frame
		}
		// (a) host discovery — the device is a host on this network.
		if s.svc != nil && edge.NeighborIP != "" {
			s.svc.Emit(NewHostEvent{IP: edge.NeighborIP, MAC: edge.NeighborMAC, Source: "cdp_frame"})
		}
		// (b) neighbor edge — local interface sees this neighbor.
		if s.neighborSink != nil {
			s.neighborSink(s.ifaceMACs[iface], []cdpEdge{edge})
		}
	}
}

// parseCDPFrame parses a CDP frame. CDP format: after Ethernet header (14 bytes),
// CDP has its own 4-byte header (version=1 byte, TTL=1 byte, checksum=2 bytes),
// then TLVs. TLV format: 2-byte type (big-endian) + 2-byte length (big-endian,
// includes type+length) + payload.
func parseCDPFrame(data []byte, srcMAC, iface, localMAC string) cdpEdge {
	edge := cdpEdge{Protocol: "CDP", NeighborMAC: srcMAC, LocalMAC: localMAC, LocalPort: iface}
	if len(data) < 4 {
		return edge // not enough for CDP header
	}
	// CDP header: version(1) + TTL(1) + checksum(2)
	// version should be 2 for CDPv2
	version := data[0]
	if version != 2 {
		return cdpEdge{Protocol: "CDP", LocalMAC: localMAC, LocalPort: iface}
	}
	// Skip CDP header (4 bytes), parse TLVs
	data = data[4:]
	for i := 0; i+4 <= len(data); {
		tlvType := binary.BigEndian.Uint16(data[i : i+2])
		tlvLength := binary.BigEndian.Uint16(data[i+2 : i+4])
		if tlvLength < 4 || i+int(tlvLength) > len(data) {
			break // invalid TLV length
		}
		payload := data[i+4 : i+int(tlvLength)]
		i += int(tlvLength)

		// End-of-data marker (type 0x0000)
		if tlvType == 0x0000 {
			break
		}

		switch tlvType {
		case 0x0001: // Device ID
			if len(payload) > 0 {
				edge.DeviceID = string(payload)
			}
		case 0x0002: // Addresses (nested TLV structure)
			// Format: number of addresses (4 bytes big-endian), then entries.
			// Each entry: protocol type (2) + protocol length (2) + protocol fields.
			// NLPID (0x0001) with IPv4 (0xcc) is the common case.
			if len(payload) >= 4 {
				numAddrs := binary.BigEndian.Uint32(payload[0:4])
				pos := 4
				for addrIdx := uint32(0); addrIdx < numAddrs && pos+4 <= len(payload); addrIdx++ {
					if pos+4 > len(payload) {
						break
					}
					protoType := binary.BigEndian.Uint16(payload[pos : pos+2])
					protoLen := binary.BigEndian.Uint16(payload[pos+2 : pos+4])
					pos += 4
					if protoLen < 1 || pos+int(protoLen) > len(payload) {
						break
					}
					addrFields := payload[pos : pos+int(protoLen)]
					pos += int(protoLen)

					if protoType == 0x0001 { // NLPID
						if len(addrFields) >= 2 && addrFields[0] == 0xcc {
							// IPv4: NLPID byte + address length byte + address
							addrLen := addrFields[1]
							if addrLen == 4 && len(addrFields) >= 2+int(addrLen) {
								ip := net.IP(addrFields[2 : 2+addrLen])
								if edge.NeighborIP == "" {
									edge.NeighborIP = ip.String()
								}
							}
						}
					}
				}
			}
		case 0x0003: // Port ID
			if len(payload) > 0 {
				edge.RemotePort = string(payload)
			}
		case 0x0004: // Capabilities (4-byte bitmap) - informational, skip
		case 0x0005: // Software Version
			if len(payload) > 0 {
				edge.SoftwareVersion = string(payload)
			}
		case 0x0006: // Platform
			if len(payload) > 0 {
				edge.Platform = string(payload)
			}
		}
	}
	return edge
}

// openCDPSocket opens an AF_PACKET raw socket bound to iface for ethertype
// 0x2000 (CDP). Requires CAP_NET_RAW.
func openCDPSocket(iface string) (int, error) {
	// AF_PACKET protocol is a network-byte-order uint16 passed as int.
	proto := int(htons(0x2000))
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
		Protocol: htons(0x2000),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		syscall.Close(sock)
		return 0, fmt.Errorf("bind: %w", err)
	}
	return sock, nil
}
