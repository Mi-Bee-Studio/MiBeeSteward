//go:build WITH_CDP

// Unit tests for CDP frame parsing. Tests the TLV parser with crafted byte
// slices; no raw socket tests.
//
// Build with: go test -tags WITH_CDP ./internal/service/scannerv2/discovery/

package discovery

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildCDPFrame builds a raw CDP frame (starting after the Ethernet header).
// Returns the CDP portion: CDP header (4 bytes: version=2, TTL, checksum) +
// serialized TLVs.
func buildCDPFrame(tlvs ...[]byte) []byte {
	// CDP header: version(2) + TTL(180) + checksum(0 = skipped by parser)
	hdr := []byte{0x02, 0xB4, 0x00, 0x00}
	for _, tlv := range tlvs {
		hdr = append(hdr, tlv...)
	}
	return hdr
}

// cdpTLV builds a single CDP TLV: type(2) + length(2) + payload(n).
func cdpTLV(tlvType uint16, payload []byte) []byte {
	totalLen := 4 + len(payload) // type(2) + length(2) + payload
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], tlvType)
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	copy(buf[4:], payload)
	return buf
}

func stringTLV(tlvType uint16, s string) []byte {
	return cdpTLV(tlvType, []byte(s))
}

func TestParseCDPFrame_EmptyData(t *testing.T) {
	edge := parseCDPFrame(nil, "aa:bb:cc:dd:ee:ff", "eth0", "11:22:33:44:55:66")
	if edge.NeighborMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected srcMAC fallback, got %q", edge.NeighborMAC)
	}
	if edge.Protocol != "CDP" {
		t.Errorf("expected protocol CDP, got %q", edge.Protocol)
	}
}

func TestParseCDPFrame_WrongVersion(t *testing.T) {
	// Version 1 frame (CDPv1 - not supported)
	data := []byte{0x01, 0xB4, 0x00, 0x00} // version=1
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.NeighborMAC != "" {
		t.Errorf("expected empty MAC for unsupported CDP version, got %q", edge.NeighborMAC)
	}
}

func TestParseCDPFrame_DeviceID(t *testing.T) {
	data := buildCDPFrame(
		stringTLV(0x0001, "Switch1.example.com"),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "11:22:33:44:55:66")
	if edge.DeviceID != "Switch1.example.com" {
		t.Errorf("expected DeviceID=Switch1.example.com, got %q", edge.DeviceID)
	}
	if edge.NeighborMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected srcMAC preserved, got %q", edge.NeighborMAC)
	}
}

func TestParseCDPFrame_PortID(t *testing.T) {
	data := buildCDPFrame(
		stringTLV(0x0003, "GigabitEthernet0/1"),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.RemotePort != "GigabitEthernet0/1" {
		t.Errorf("expected RemotePort=GigabitEthernet0/1, got %q", edge.RemotePort)
	}
}

func TestParseCDPFrame_Platform(t *testing.T) {
	data := buildCDPFrame(
		stringTLV(0x0006, "cisco WS-C2960-24TC-L"),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.Platform != "cisco WS-C2960-24TC-L" {
		t.Errorf("expected Platform=cisco WS-C2960-24TC-L, got %q", edge.Platform)
	}
}

func TestParseCDPFrame_SoftwareVersion(t *testing.T) {
	data := buildCDPFrame(
		stringTLV(0x0005, "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(4)E8"),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.SoftwareVersion != "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(4)E8" {
		t.Errorf("unexpected SoftwareVersion: %q", edge.SoftwareVersion)
	}
}

// buildAddressTLV builds a CDP Address TLV (type 0x0002) with one IPv4 address.
func buildAddressTLV(ipv4 string) []byte {
	ip := net.ParseIP(ipv4).To4()
	if ip == nil {
		panic("bad ipv4: " + ipv4)
	}
	// Address entry for NLPID/IPv4:
	// protocol type (2) + protocol length (2) + NLPID byte (1) + addr len (1) + addr (4)
	entry := make([]byte, 10)
	binary.BigEndian.PutUint16(entry[0:2], 0x0001) // NLPID
	binary.BigEndian.PutUint16(entry[2:4], 6)      // protocol length = 1 + 1 + 4
	entry[4] = 0xcc                                // NLPID = IPv4
	entry[5] = 4                                   // addr len
	copy(entry[6:10], ip)                          // IPv4 address

	// TLV payload: number of addresses (4-byte) + entries
	tlvPayload := make([]byte, 4+len(entry))
	binary.BigEndian.PutUint32(tlvPayload[0:4], 1) // 1 address
	copy(tlvPayload[4:], entry)

	return cdpTLV(0x0002, tlvPayload)
}

func TestParseCDPFrame_AddressIPv4(t *testing.T) {
	data := buildCDPFrame(
		buildAddressTLV("192.168.1.1"),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.NeighborIP != "192.168.1.1" {
		t.Errorf("expected NeighborIP=192.168.1.1, got %q", edge.NeighborIP)
	}
}

func TestParseCDPFrame_FullFrame(t *testing.T) {
	// Simulate a typical CDP frame from a Cisco Catalyst switch.
	data := buildCDPFrame(
		stringTLV(0x0001, "Catalyst-3750-01"),
		buildAddressTLV("10.0.0.1"),
		stringTLV(0x0003, "GigabitEthernet1/0/1"),
		stringTLV(0x0006, "cisco WS-C3750G-24TS-S1U"),
		stringTLV(0x0005, "Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(55)SE11"),
	)
	edge := parseCDPFrame(data, "00:11:22:33:44:55", "eth0", "aa:bb:cc:dd:ee:ff")
	if edge.DeviceID != "Catalyst-3750-01" {
		t.Errorf("DeviceID: got %q", edge.DeviceID)
	}
	if edge.NeighborIP != "10.0.0.1" {
		t.Errorf("NeighborIP: got %q", edge.NeighborIP)
	}
	if edge.RemotePort != "GigabitEthernet1/0/1" {
		t.Errorf("RemotePort: got %q", edge.RemotePort)
	}
	if edge.Platform != "cisco WS-C3750G-24TS-S1U" {
		t.Errorf("Platform: got %q", edge.Platform)
	}
	if edge.SoftwareVersion != "Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(55)SE11" {
		t.Errorf("SoftwareVersion: got %q", edge.SoftwareVersion)
	}
	if edge.NeighborMAC != "00:11:22:33:44:55" {
		t.Errorf("NeighborMAC: got %q", edge.NeighborMAC)
	}
	if edge.LocalMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("LocalMAC: got %q", edge.LocalMAC)
	}
	if edge.LocalPort != "eth0" {
		t.Errorf("LocalPort: got %q", edge.LocalPort)
	}
	if edge.Protocol != "CDP" {
		t.Errorf("Protocol: got %q", edge.Protocol)
	}
}

func TestParseCDPFrame_UnknownTLVsAreSkipped(t *testing.T) {
	// Unknown TLV type followed by Device ID — parser should skip unknown and
	// continue to parse known ones.
	data := buildCDPFrame(
		stringTLV(0x00FF, "some-unknown-data"),
		stringTLV(0x0001, "Switch42"),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.DeviceID != "Switch42" {
		t.Errorf("expected DeviceID=Switch42 after skipping unknown TLV, got %q", edge.DeviceID)
	}
}

func TestParseCDPFrame_ZeroLengthPayload(t *testing.T) {
	// TLV with type=0x0001 (DeviceID) but empty payload.
	data := buildCDPFrame(
		cdpTLV(0x0001, nil),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.DeviceID != "" {
		t.Errorf("expected empty DeviceID for zero-length payload, got %q", edge.DeviceID)
	}
}

func TestParseCDPFrame_EndMarker(t *testing.T) {
	// Type 0x0000 terminates parsing; subsequent TLVs are ignored.
	data := buildCDPFrame(
		stringTLV(0x0001, "BeforeEnd"),
		cdpTLV(0x0000, nil),
		stringTLV(0x0001, "AfterEnd"),
	)
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.DeviceID != "BeforeEnd" {
		t.Errorf("expected DeviceID=BeforeEnd (before end marker), got %q", edge.DeviceID)
	}
}

func TestParseCDPFrame_TruncatedTLV(t *testing.T) {
	// A TLV whose length exceeds the available data — should stop gracefully.
	data := buildCDPFrame(
		cdpTLV(0x0001, []byte("Switch1")),
	)
	// Corrupt the frame by truncating before the last TLV.
	data = data[:len(data)-3]
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	// Should not panic; DeviceID may or may not be parsed depending on where
	// truncation hits. The edge must still be returned (graceful degradation).
	if edge.NeighborMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected srcMAC preserved despite truncation, got %q", edge.NeighborMAC)
	}
}

func TestParseCDPFrame_MultipleAddresses(t *testing.T) {
	// Two IPv4 addresses; first one wins.
	ip1 := net.ParseIP("10.0.0.1").To4()
	ip2 := net.ParseIP("10.0.0.2").To4()

	entry := func(ip net.IP) []byte {
		b := make([]byte, 10)
		binary.BigEndian.PutUint16(b[0:2], 0x0001) // NLPID
		binary.BigEndian.PutUint16(b[2:4], 6)      // proto len
		b[4] = 0xcc                                // IPv4
		b[5] = 4
		copy(b[6:10], ip)
		return b
	}

	tlvPayload := make([]byte, 4+len(entry(ip1))+len(entry(ip2)))
	binary.BigEndian.PutUint32(tlvPayload[0:4], 2) // 2 addresses
	copy(tlvPayload[4:], entry(ip1))
	copy(tlvPayload[4+len(entry(ip1)):], entry(ip2))

	data := buildCDPFrame(cdpTLV(0x0002, tlvPayload))
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.NeighborIP != "10.0.0.1" {
		t.Errorf("expected first IPv4=10.0.0.1, got %q", edge.NeighborIP)
	}
}

func TestParseCDPFrame_EmptyFrame(t *testing.T) {
	// Only CDP header, no TLVs at all.
	data := buildCDPFrame()
	edge := parseCDPFrame(data, "aa:bb:cc:dd:ee:ff", "eth0", "")
	if edge.NeighborMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected srcMAC preserved for frame with no TLVs, got %q", edge.NeighborMAC)
	}
}
