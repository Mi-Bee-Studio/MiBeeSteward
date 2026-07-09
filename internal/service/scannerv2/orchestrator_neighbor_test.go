package scannerv2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtractNeighbors verifies the evidence→NeighborSpec extraction: only
// "neighbor"-kind evidence is pulled, and (neighbor_mac, protocol) pairs are
// deduped within one host's evidence set.
func TestExtractNeighbors(t *testing.T) {
	ev := []Evidence{
		{Kind: "port_open", Port: 80}, // ignored
		{Kind: "neighbor", RawData: map[string]string{
			"neighbor_mac": "aa:bb:cc:dd:ee:01", "protocol": "Bridge-MIB", "local_port": "5",
		}},
		{Kind: "neighbor", RawData: map[string]string{
			"neighbor_mac": "aa:bb:cc:dd:ee:02", "protocol": "Bridge-MIB", "local_port": "6",
		}},
		// Duplicate (same mac+protocol) — should be deduped.
		{Kind: "neighbor", RawData: map[string]string{
			"neighbor_mac": "aa:bb:cc:dd:ee:01", "protocol": "Bridge-MIB", "local_port": "5",
		}},
		// Missing mac — skipped.
		{Kind: "neighbor", RawData: map[string]string{"protocol": "LLDP"}},
	}
	neighbors := extractNeighbors(ev)
	require.Len(t, neighbors, 2, "two unique neighbors after dedup")
	require.Equal(t, "aa:bb:cc:dd:ee:01", neighbors[0].NeighborMAC)
	require.Equal(t, "Bridge-MIB", neighbors[0].Protocol)
	require.Equal(t, "5", neighbors[0].LocalPort)
}

// TestExtractNeighbors_Empty confirms no-neighbor evidence yields nil.
func TestExtractNeighbors_Empty(t *testing.T) {
	require.Nil(t, extractNeighbors(nil))
	require.Nil(t, extractNeighbors([]Evidence{{Kind: "port_open"}}))
}
