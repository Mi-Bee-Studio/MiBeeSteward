package probe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIndexSuffixForIfName verifies the OID index suffix extraction for IF-MIB OIDs.
// The dot1dBasePortIfIndex OID index is the bridge port number (single integer).
// The ifName OID index is the ifIndex (single integer).
func TestIndexSuffixForIfName(t *testing.T) {
	cases := []struct {
		full, prefix, want string
	}{
		// dot1dBasePortIfIndex: bridge port 3 → ifIndex 5
		{".1.3.6.1.2.1.17.1.4.1.2.3", "1.3.6.1.2.1.17.1.4.1.2", "3"},
		{".1.3.6.1.2.1.17.1.4.1.2.10", "1.3.6.1.2.1.17.1.4.1.2", "10"},
		// ifName: ifIndex 5 → "ge-0/0/3"
		{".1.3.6.1.2.1.31.1.1.1.1.5", "1.3.6.1.2.1.31.1.1.1.1", "5"},
		{".1.3.6.1.2.1.31.1.1.1.1.100", "1.3.6.1.2.1.31.1.1.1.1", "100"},
		// Edge cases
		{".1.3.6.1.2.1.17.1.4.1.2", "1.3.6.1.2.1.17.1.4.1.2", ""}, // no index
		{".1.2.3.4.5", "9.8.7", ""},                               // prefix doesn't match
	}
	for _, c := range cases {
		got := indexSuffix(c.full, c.prefix)
		require.Equal(t, c.want, got, "indexSuffix(%q, %q)", c.full, c.prefix)
	}
}

// TestGosnmpToInt verifies the integer extraction from gosnmp varbind values.
func TestGosnmpToInt(t *testing.T) {
	cases := []struct {
		val  any
		want int
	}{
		{int(5), 5},
		{int64(10), 10},
		{uint(15), 15},
		{uint64(20), 20},
		{"string", 0},     // wrong type
		{nil, 0},          // nil
		{float64(1.5), 0}, // float not handled
	}
	for _, c := range cases {
		got := gosnmpToInt(c.val)
		require.Equal(t, c.want, got, "gosnmpToInt(%v)", c.val)
	}
}

// TestResolvePortNamesNilSNMP verifies that ResolvePortNames returns nil for nil input.
func TestResolvePortNamesNilSNMP(t *testing.T) {
	got := ResolvePortNames(nil, nil)
	require.Nil(t, got)
}

// TestBridgeMIBProbeName verifies the probe name contract.
func TestBridgeMIBProbeName(t *testing.T) {
	p := NewBridgeMIBProbe(nil)
	require.Equal(t, "active:bridge_mib", p.Name())
}
