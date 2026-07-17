package probe

import (
	"testing"
)

func TestNewCDPMIBProbe(t *testing.T) {
	probe := NewCDPMIBProbe(nil)
	if probe == nil {
		t.Fatal("NewCDPMIBProbe(nil) returned nil")
	}
	if probe.Name() != "active:cdp_mib" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "active:cdp_mib")
	}
}

func TestCDPIfIndexFromIndex(t *testing.T) {
	tests := []struct {
		name   string
		suffix string
		want   int
	}{
		{
			name:   "valid single integer index",
			suffix: "5",
			want:   5,
		},
		{
			name:   "valid ifIndex 1",
			suffix: "1",
			want:   1,
		},
		{
			name:   "valid ifIndex 1000",
			suffix: "1000",
			want:   1000,
		},
		{
			name:   "empty string",
			suffix: "",
			want:   0,
		},
		{
			name:   "multi-part index (invalid for CDP)",
			suffix: "1.2",
			want:   0,
		},
		{
			name:   "non-numeric",
			suffix: "abc",
			want:   0,
		},
		{
			name:   "zero",
			suffix: "0",
			want:   0,
		},
		{
			name:   "negative (can't parse)",
			suffix: "-1",
			want:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cdpIfIndexFromIndex(tt.suffix)
			if got != tt.want {
				t.Errorf("cdpIfIndexFromIndex(%q) = %d, want %d", tt.suffix, got, tt.want)
			}
		})
	}
}

func TestExtractIPv4FromCDPAddress(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "valid IPv4 192.168.1.1",
			// type=1, len=6, NLPID=0xcc (IPv4), addrLen=4, addr=192.168.1.1
			data: []byte{0x01, 0x06, 0xcc, 0x04, 0xc0, 0xa8, 0x01, 0x01},
			want: "192.168.1.1",
		},
		{
			name: "valid IPv4 10.0.0.1",
			// type=1, len=6, NLPID=0xcc (IPv4), addrLen=4, addr=10.0.0.1
			data: []byte{0x01, 0x06, 0xcc, 0x04, 0x0a, 0x00, 0x00, 0x01},
			want: "10.0.0.1",
		},
		{
			name: "valid IPv4 0.0.0.0",
			// type=1, len=6, NLPID=0xcc (IPv4), addrLen=4, addr=0.0.0.0
			data: []byte{0x01, 0x06, 0xcc, 0x04, 0x00, 0x00, 0x00, 0x00},
			want: "0.0.0.0",
		},
		{
			name: "valid IPv4 255.255.255.255",
			// type=1, len=6, NLPID=0xcc (IPv4), addrLen=4, addr=255.255.255.255
			data: []byte{0x01, 0x06, 0xcc, 0x04, 0xff, 0xff, 0xff, 0xff},
			want: "255.255.255.255",
		},
		{
			name: "wrong type (not IPv4)",
			data: []byte{0x02, 0x06, 0xcc, 0x04, 0xc0, 0xa8, 0x01, 0x01},
			want: "",
		},
		{
			name: "wrong NLPID (not IPv4)",
			data: []byte{0x01, 0x06, 0xaa, 0x04, 0xc0, 0xa8, 0x01, 0x01},
			want: "",
		},
		{
			name: "too short (< 5 bytes)",
			data: []byte{0x01, 0x06, 0xcc, 0x04},
			want: "",
		},
		{
			name: "wrong addrLen (not 4)",
			data: []byte{0x01, 0x06, 0xcc, 0x06, 0xc0, 0xa8, 0x01, 0x01},
			want: "",
		},
		{
			name: "insufficient data for declared addrLen",
			data: []byte{0x01, 0x06, 0xcc, 0x08, 0xc0, 0xa8, 0x01, 0x01},
			want: "",
		},
		{
			name: "empty data",
			data: []byte{},
			want: "",
		},
		{
			name: "nil data",
			data: nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIPv4FromCDPAddress(tt.data)
			if got != tt.want {
				t.Errorf("extractIPv4FromCDPAddress(%v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestFormatIPv4(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{
			name: "valid IPv4 192.168.1.1",
			b:    []byte{192, 168, 1, 1},
			want: "192.168.1.1",
		},
		{
			name: "valid IPv4 10.0.0.1",
			b:    []byte{10, 0, 0, 1},
			want: "10.0.0.1",
		},
		{
			name: "valid IPv4 0.0.0.0",
			b:    []byte{0, 0, 0, 0},
			want: "0.0.0.0",
		},
		{
			name: "valid IPv4 255.255.255.255",
			b:    []byte{255, 255, 255, 255},
			want: "255.255.255.255",
		},
		{
			name: "too short",
			b:    []byte{192, 168, 1},
			want: "",
		},
		{
			name: "too long",
			b:    []byte{192, 168, 1, 1, 0},
			want: "",
		},
		{
			name: "empty",
			b:    []byte{},
			want: "",
		},
		{
			name: "nil",
			b:    nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatIPv4(tt.b)
			if got != tt.want {
				t.Errorf("formatIPv4(%v) = %q, want %q", tt.b, got, tt.want)
			}
		})
	}
}
