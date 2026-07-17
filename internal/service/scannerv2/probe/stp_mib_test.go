package probe

import (
	"testing"
)

func TestNewSTPMIBProbe(t *testing.T) {
	p := NewSTPMIBProbe(nil)
	if got := p.Name(); got != "active:stp_mib" {
		t.Errorf("Name() = %q, want %q", got, "active:stp_mib")
	}
}

func TestExtractBridgeMACFromDesignatedBridge(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "valid 8-byte value",
			input: []byte{0x80, 0x00, 0x00, 0x1a, 0xbb, 0xcc, 0xdd, 0xee},
			want:  "00:1a:bb:cc:dd:ee",
		},
		{
			name:  "too short (7 bytes)",
			input: []byte{0x80, 0x00, 0x00, 0x1a, 0xbb, 0xcc, 0xdd},
			want:  "",
		},
		{
			name:  "too long (9 bytes)",
			input: []byte{0x80, 0x00, 0x00, 0x1a, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			want:  "",
		},
		{
			name:  "zeros",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want:  "00:00:00:00:00:00",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBridgeMACFromDesignatedBridge(tt.input)
			if got != tt.want {
				t.Errorf("extractBridgeMACFromDesignatedBridge(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
