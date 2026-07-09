package probe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMacIndexToMAC verifies the Bridge-MIB OID-index-to-MAC conversion: the
// dot1dTpFdbTable indexes rows by the MAC address as 6 decimal octet sub-OIDs
// (e.g. ".170.187.204.221.238.255" → aa:bb:cc:dd:ee:ff).
func TestMacIndexToMAC(t *testing.T) {
	cases := []struct {
		suffix string
		want   string
	}{
		{"170.187.204.221.238.255", "aa:bb:cc:dd:ee:ff"},
		{"0.1.2.3.4.5", "00:01:02:03:04:05"},
		{"255.255.255.255.255.255", "ff:ff:ff:ff:ff:ff"},
		{"1.2.3.4.5", ""},          // too few octets
		{"1.2.3.4.5.6.7", ""},      // too many
		{"1.2.3.4.5.256", ""},      // octet > 255
		{"", ""},                   // empty
		{"abc", ""},                // non-numeric
	}
	for _, c := range cases {
		got := macIndexToMAC(c.suffix)
		require.Equal(t, c.want, got, "macIndexToMAC(%q)", c.suffix)
	}
}

// TestIndexSuffix verifies the OID-prefix stripping for Bridge-MIB indexes.
func TestIndexSuffix(t *testing.T) {
	cases := []struct {
		full, prefix, want string
	}{
		{".1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255", "1.3.6.1.2.1.17.4.3.1.2", "170.187.204.221.238.255"},
		{"1.3.6.1.2.1.17.4.3.1.2.10.20.30.40.50.60", "1.3.6.1.2.1.17.4.3.1.2", "10.20.30.40.50.60"},
		{".1.2.3.4.5", "9.8.7", ""}, // prefix doesn't match
	}
	for _, c := range cases {
		got := indexSuffix(c.full, c.prefix)
		require.Equal(t, c.want, got, "indexSuffix(%q, %q)", c.full, c.prefix)
	}
}
