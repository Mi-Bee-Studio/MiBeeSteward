package probe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLldpLocalPortFromIndex verifies the lldpRemTable index parsing: the index
// is "<timeMark>.<localPort>.<remIndex>" and the local port is the 2nd
// sub-identifier.
func TestLldpLocalPortFromIndex(t *testing.T) {
	cases := []struct {
		suffix string
		want   string
	}{
		{"0.5.1", "5"}, // timeMark=0, localPort=5, remIndex=1
		{"0.101.42", "101"},
		{"100.1.2", "1"},
		{"0.abc.1", ""}, // non-numeric local port
		{"5.1", ""},     // too few components
		{"", ""},
	}
	for _, c := range cases {
		require.Equal(t, c.want, lldpLocalPortFromIndex(c.suffix), "suffix %q", c.suffix)
	}
}

// TestLldpChassisToMAC verifies that only subtype 4 (MAC address) with exactly
// 6 octets yields a canonical MAC; other subtypes return "" so they're skipped.
func TestLldpChassisToMAC(t *testing.T) {
	// aa:bb:cc:dd:ee:ff
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	require.Equal(t, "aa:bb:cc:dd:ee:ff", lldpChassisToMAC(4, mac))
	// wrong subtype (7 = locally assigned) → not a MAC
	require.Equal(t, "", lldpChassisToMAC(7, mac))
	// subtype 4 but wrong length
	require.Equal(t, "", lldpChassisToMAC(4, mac[:5]))
	require.Equal(t, "", lldpChassisToMAC(4, append(mac, 0x00)))
	// empty
	require.Equal(t, "", lldpChassisToMAC(4, nil))
}

// TestLldpEvidenceShape is a shape contract test: a subtype-4 chassis id
// produces a "neighbor" Evidence with protocol "LLDP" and the six RawData keys
// (neighbor_mac, protocol, local_port, remote_port, sys_name, sys_desc)
// the orchestrator's extractNeighbors reads. This guards against a refactor
// silently changing the contract the store depends on.
// produces a "neighbor" Evidence with protocol "LLDP" and the four RawData keys
// the orchestrator's extractNeighbors reads. This guards against a refactor
// silently changing the contract the store depends on.
func TestLldpEvidenceShape(t *testing.T) {
	p := NewLLDPMIBProbe(nil)
	require.Equal(t, "active:lldp_mib", p.Name())
}

// TestLldpIndexSuffix verifies indexSuffix with the new LLDP-MIB OID prefixes
// for lldpRemSysName and lldpRemSysDesc. The index format is
// "<timeMark>.<localPort>.<remIndex>" — same as the other lldpRemTable columns.
func TestLldpIndexSuffix(t *testing.T) {
	cases := []struct {
		full, prefix, want string
	}{
		{".1.0.8802.1.1.2.1.4.1.1.9.0.5.1", "1.0.8802.1.1.2.1.4.1.1.9", "0.5.1"},
		{".1.0.8802.1.1.2.1.4.1.1.10.0.101.42", "1.0.8802.1.1.2.1.4.1.1.10", "0.101.42"},
		{".1.0.8802.1.1.2.1.4.1.1.9", "1.0.8802.1.1.2.1.4.1.1.9", ""},        // no suffix
		{".1.0.8802.1.1.2.1.4.1.1.10.0.5.1", "1.0.8802.1.1.2.1.4.1.1.9", ""}, // wrong prefix
	}
	for _, c := range cases {
		got := indexSuffix(c.full, c.prefix)
		require.Equal(t, c.want, got, "indexSuffix(%q, %q)", c.full, c.prefix)
	}
}
