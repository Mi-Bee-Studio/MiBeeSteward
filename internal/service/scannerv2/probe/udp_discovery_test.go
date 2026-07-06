package probe

import (
	"testing"
)

func TestBuildMDNSQuery(t *testing.T) {
	msg := buildMDNSQuery("_onvif._tcp.local")
	// Header is 12 bytes.
	if len(msg) < 12 {
		t.Fatalf("query too short: %d bytes", len(msg))
	}
	// QDCOUNT should be 1.
	qdcount := int(msg[4])<<8 | int(msg[5])
	if qdcount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdcount)
	}
	// QTYPE (PTR=12) is the last 2 bytes before QCLASS; verify the trailing
	// QCLASS has the cache-flush bit (0x80, 0x01).
	if msg[len(msg)-2] != 0x80 || msg[len(msg)-1] != 0x01 {
		t.Errorf("QCLASS = % x, want 80 01 (cache-flush + IN)", msg[len(msg)-2:])
	}
}

func TestReadDNSName_NoCompression(t *testing.T) {
	// "_onvif._tcp.local" encoded as length-prefixed labels + null terminator.
	enc := []byte{
		6, '_', 'o', 'n', 'v', 'i', 'f',
		4, '_', 't', 'c', 'p',
		5, 'l', 'o', 'c', 'a', 'l',
		0,
	}
	name, next, err := readDNSName(enc, 0)
	if err != nil {
		t.Fatalf("readDNSName: %v", err)
	}
	if name != "_onvif._tcp.local" {
		t.Errorf("name = %q, want _onvif._tcp.local", name)
	}
	if next != len(enc) {
		t.Errorf("next = %d, want %d (past name + null)", next, len(enc))
	}
}

func TestReadDNSName_CompressionPointer(t *testing.T) {
	// Two names: "foo.local" at offset 0, then a pointer to it.
	enc := []byte{
		3, 'f', 'o', 'o', 5, 'l', 'o', 'c', 'a', 'l', 0, // "foo.local" at 0..10
		3, 'b', 'a', 'r', 0xC0, 0x00, // "bar" + pointer to offset 0
	}
	name, _, err := readDNSName(enc, 11) // read the second name
	if err != nil {
		t.Fatalf("readDNSName: %v", err)
	}
	if name != "bar.foo.local" {
		t.Errorf("name = %q, want bar.foo.local", name)
	}
}

func TestDnsStripLocal(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cam-front.local", "cam-front"},
		{"_onvif._tcp.local", "_onvif._tcp"},
		{"plain", "plain"},
		{"trailing.", "trailing"},
		{"", ""},
	}
	for _, c := range cases {
		if got := dnsStripLocal(c.in); got != c.want {
			t.Errorf("dnsStripLocal(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEncodeNetbiosName(t *testing.T) {
	// 15-char name padded → 30 encoded chars, + 2 for the suffix byte = 32 total.
	enc := encodeNetbiosName("*", 0x00)
	if len(enc) != 32 {
		t.Fatalf("encoded length = %d, want 32", len(enc))
	}
	// "*" = 0x2A → nibbles 2,A → 'C','K'. The first two chars must be "CK".
	if string(enc[:2]) != "CK" {
		t.Errorf("first encoded bytes = %q, want CK", enc[:2])
	}
	// The rest of the 15-char padding is spaces (0x20) → each space encodes as
	// "CA" (high nibble 2 → 'C', low nibble 0 → 'A'). "*" is 1 char so 14 padding
	// spaces follow = "CA" × 14 = "CACA...".
	if string(enc[2:30]) != "CACACACACACACACACACACACACACA" {
		t.Errorf("padded section = %q", enc[2:30])
	}
}

func TestParseNetbiosResponse(t *testing.T) {
	// Construct a minimal NBNS Node Status Response: 56-byte header, num_names=1,
	// then one 18-byte entry for "MYHOST" (workstation, suffix 0x00, unique).
	msg := make([]byte, 57+18)
	// num_names at offset 56
	msg[56] = 1
	// entry: 15-char name + suffix + 2-byte flags
	copy(msg[57:], []byte("MYHOST          "))
	msg[57+15] = 0x00 // suffix = workstation
	msg[57+16] = 0x00 // flags high byte (unique, not group)
	msg[57+17] = 0x00

	host, wg := parseNetbiosResponse(msg)
	if host != "MYHOST" {
		t.Errorf("host = %q, want MYHOST", host)
	}
	if wg != "" {
		t.Errorf("workgroup = %q, want empty", wg)
	}
}

func TestParseNetbiosResponse_Workgroup(t *testing.T) {
	// Two entries: a unique WORKSTATION name + a group WORKGROUP name (both
	// suffix 0x00, but the group one has the 0x8000 flag set).
	msg := make([]byte, 57+18*2)
	msg[56] = 2
	// entry 1: unique workstation "WS01"
	copy(msg[57:], []byte("WS01            "))
	msg[57+15] = 0x00
	msg[57+16] = 0x00 // unique
	msg[57+17] = 0x00
	// entry 2: group "MYDOMAIN"
	copy(msg[57+18:], []byte("MYDOMAIN        "))
	msg[57+18+15] = 0x00
	msg[57+18+16] = 0x80 // group bit (0x8000)
	msg[57+18+17] = 0x00

	host, wg := parseNetbiosResponse(msg)
	if host != "WS01" {
		t.Errorf("host = %q, want WS01", host)
	}
	if wg != "MYDOMAIN" {
		t.Errorf("workgroup = %q, want MYDOMAIN", wg)
	}
}

func TestParseSSDPResponse(t *testing.T) {
	pkt := []byte("HTTP/1.1 200 OK\r\n" +
		"LOCATION: http://192.168.63.40:50000/desc.xml\r\n" +
		"SERVER: Linux/4.4 UPnP/1.1 MyDevice/1.0\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"\r\n")
	raw := parseSSDPResponse(pkt)
	if raw["server"] != "Linux/4.4 UPnP/1.1 MyDevice/1.0" {
		t.Errorf("server = %q", raw["server"])
	}
	if raw["location"] != "http://192.168.63.40:50000/desc.xml" {
		t.Errorf("location = %q", raw["location"])
	}
	if raw["st"] != "upnp:rootdevice" {
		t.Errorf("st = %q", raw["st"])
	}
}

func TestIndexToIP(t *testing.T) {
	// Full OID with trailing index "2.192.168.63.133" (ifIndex=2, IP=192.168.63.133)
	full := ".1.3.6.1.2.1.4.22.1.2.2.192.168.63.133"
	prefix := oidIPNetToMediaPhysAddress
	got := indexToIP(full, prefix)
	if got != "192.168.63.133" {
		t.Errorf("indexToIP = %q, want 192.168.63.133", got)
	}
	// Non-matching prefix → "".
	if got := indexToIP(full, "1.2.3"); got != "" {
		t.Errorf("non-matching prefix should return empty, got %q", got)
	}
}

func TestFormatMAC(t *testing.T) {
	mac := formatMAC([]byte{0xbc, 0xad, 0x28, 0x11, 0x22, 0x33})
	if mac != "bc:ad:28:11:22:33" {
		t.Errorf("formatMAC = %q", mac)
	}
}

func TestSnmpOctetsToMAC(t *testing.T) {
	// 6 bytes → MAC.
	mac := snmpOctetsToMAC([]byte{0xbc, 0xad, 0x28, 0x11, 0x22, 0x33})
	if mac != "bc:ad:28:11:22:33" {
		t.Errorf("got %q", mac)
	}
	// Wrong length → "".
	if snmpOctetsToMAC([]byte{0x01, 0x02}) != "" {
		t.Error("non-6-byte value should return empty")
	}
	// Non-bytes → "".
	if snmpOctetsToMAC("not bytes") != "" {
		t.Error("non-[]byte value should return empty")
	}
}
