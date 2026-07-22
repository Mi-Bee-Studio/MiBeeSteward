package probe

import (
	"testing"
)

func TestNewQBridgeMIBProbe(t *testing.T) {
	probe := NewQBridgeMIBProbe(nil)
	if probe == nil {
		t.Fatal("NewQBridgeMIBProbe(nil) returned nil")
	}
	if probe.Name() != "active:q_bridge_mib" {
		t.Errorf("Expected Name() to be 'active:q_bridge_mib', got '%s'", probe.Name())
	}
}

func TestExtractMACFromVLANIndex(t *testing.T) {
	tests := []struct {
		name    string
		index   string
		want    string
		wantErr bool
	}{
		{
			name:    "Single-octet VLAN (VLAN 1) with MAC aa:bb:cc:dd:ee:ff",
			index:   "1.170.187.204.221.238.255",
			want:    "170.187.204.221.238.255",
			wantErr: false,
		},
		{
			name:    "Single-octet VLAN (VLAN 100) with MAC 0a:00:01:02:03:04",
			index:   "100.10.0.1.2.3.4",
			want:    "10.0.1.2.3.4",
			wantErr: false,
		},
		{
			name:    "Two-octet VLAN (VLAN 4096) with MAC 0a:00:01:02:03:04",
			index:   "4096.10.0.1.2.3.4",
			want:    "10.0.1.2.3.4",
			wantErr: false,
		},
		{
			name:    "Two-octet VLAN (VLAN 1000) with MAC aa:bb:cc:dd:ee:ff",
			index:   "1000.170.187.204.221.238.255",
			want:    "170.187.204.221.238.255",
			wantErr: false,
		},
		{
			name:    "Zero MAC address (all zeros)",
			index:   "1.0.0.0.0.0.0",
			want:    "0.0.0.0.0.0",
			wantErr: false,
		},
		{
			name:    "Broadcast MAC (ff:ff:ff:ff:ff:ff)",
			index:   "1.255.255.255.255.255.255",
			want:    "255.255.255.255.255.255",
			wantErr: false,
		},
		{
			name:    "Empty index",
			index:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Too short (only 5 MAC octets)",
			index:   "1.170.187.204.221.238",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Only MAC octets (no VLAN prefix) — invalid for Q-BRIDGE",
			index:   "170.187.204.221.238.255",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMACFromVLANIndex(tt.index)
			if got != tt.want {
				t.Errorf("extractMACFromVLANIndex(%q) = %q, want %q", tt.index, got, tt.want)
			}
			if tt.wantErr && got != "" {
				t.Errorf("extractMACFromVLANIndex(%q) = %q, expected empty for error case", tt.index, got)
			}
		})
	}
}

func TestExtractMACFromVLANIndexToMACConversion(t *testing.T) {
	tests := []struct {
		name  string
		index string
		want  string
	}{
		{
			name:  "VLAN 1, MAC aa:bb:cc:dd:ee:ff",
			index: "1.170.187.204.221.238.255",
			want:  "aa:bb:cc:dd:ee:ff",
		},
		{
			name:  "VLAN 100, MAC 0a:00:01:02:03:04",
			index: "100.10.0.1.2.3.4",
			want:  "0a:00:01:02:03:04",
		},
		{
			name:  "VLAN 4096, MAC 00:11:22:33:44:55",
			index: "4096.0.17.34.51.68.85",
			want:  "00:11:22:33:44:55",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			macIdx := extractMACFromVLANIndex(tt.index)
			if macIdx == "" {
				t.Fatalf("extractMACFromVLANIndex(%q) returned empty", tt.index)
			}
			got := macIndexToMAC(macIdx)
			if got != tt.want {
				t.Errorf("MAC conversion: extractMACFromVLANIndex(%q) = %q, macIndexToMAC(%q) = %q, want %q",
					tt.index, macIdx, macIdx, got, tt.want)
			}
		})
	}
}

func TestQBridgeOIDPrefixHandling(t *testing.T) {
	// Verify that the OID prefix is correct and indexSuffix works as expected
	fullOID := ".1.3.6.1.2.1.17.7.1.2.2.1.2.1.170.187.204.221.238.255"
	prefix := oidDot1qTpFdbPort
	expectedSuffix := "1.170.187.204.221.238.255"

	got := indexSuffix(fullOID, prefix)
	if got != expectedSuffix {
		t.Errorf("indexSuffix(%q, %q) = %q, want %q", fullOID, prefix, got, expectedSuffix)
	}

	// Test with a different VLAN
	fullOID2 := ".1.3.6.1.2.1.17.7.1.2.2.1.2.100.10.0.1.2.3.4"
	expectedSuffix2 := "100.10.0.1.2.3.4"

	got2 := indexSuffix(fullOID2, prefix)
	if got2 != expectedSuffix2 {
		t.Errorf("indexSuffix(%q, %q) = %q, want %q", fullOID2, prefix, got2, expectedSuffix2)
	}

	// Test with two-octet VLAN
	fullOID3 := ".1.3.6.1.2.1.17.7.1.2.2.1.2.4096.10.0.1.2.3.4"
	expectedSuffix3 := "4096.10.0.1.2.3.4"

	got3 := indexSuffix(fullOID3, prefix)
	if got3 != expectedSuffix3 {
		t.Errorf("indexSuffix(%q, %q) = %q, want %q", fullOID3, prefix, got3, expectedSuffix3)
	}
}

// TestExtractVLANFromIndex verifies the VLAN tag parser extracts the correct
// 802.1Q tag (1-4094) from both 1-octet and 2-octet OID index forms, and
// rejects invalid tags. This is the parser that feeds the vlans table —
// previously the VLAN prefix was discarded at MAC extraction, leaving vlans
// permanently empty.
func TestExtractVLANFromIndex(t *testing.T) {
	// Index form: <VLAN-octets>.<6 MAC-octets>. Single-octet VLAN = 7 total
	// segments; two-octet VLAN = 8 total segments. extractVLANFromIndex takes
	// everything before the last 6 segments as the VLAN prefix.
	tests := []struct {
		name  string
		index string
		want  string
	}{
		{"single-octet vlan 1", "1.170.187.204.221.238.255", "1"},
		{"single-octet vlan 100 (7 segs)", "100.10.0.1.2.3.4", "100"},
		{"two-octet vlan 256 (1<<8|0, 8 segs)", "1.0.10.0.1.2.3.4", "256"},
		{"two-octet vlan 4094 max valid (15<<8|254)", "15.254.10.0.1.2.3.4", "4094"},
		{"too short (6 segs)", "1.2.3.4.5.6", ""},
		{"vlan 0 invalid (single octet)", "0.10.0.1.2.3.4", ""},
		{"non-numeric prefix", "x.10.0.1.2.3.4", ""},
		{"vlan 4095 reserved (15<<8|255)", "15.255.10.0.1.2.3.4", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractVLANFromIndex(tt.index); got != tt.want {
				t.Errorf("extractVLANFromIndex(%q) = %q, want %q", tt.index, got, tt.want)
			}
		})
	}
}

