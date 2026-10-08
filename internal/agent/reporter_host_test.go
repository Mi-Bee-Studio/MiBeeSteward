package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestHostToReported_NeighborsExtraction verifies "neighbor"-kind evidence
// rides the wire as the neighbors array: MAC normalization, (mac, protocol)
// dedup, identity hints carried, and non-neighbor evidence ignored.
func TestHostToReported_NeighborsExtraction(t *testing.T) {
	rep := scannerv2.HostReport{
		IP:    "192.168.2.10",
		Alive: true,
		Evidence: []scannerv2.Evidence{
			{
				Source: "active:lldp_mib", Kind: "neighbor", IP: "192.168.2.10",
				RawData: map[string]string{
					"neighbor_mac": "AA-BB-CC-DD-EE-01", "protocol": "LLDP",
					"local_port": "10", "remote_port": "swp1",
					"sys_name": "sw-core", "sys_desc": "Juniper EX4300",
				},
			},
			{
				Source: "active:lldp_mib", Kind: "neighbor", IP: "192.168.2.10",
				RawData: map[string]string{
					// same (mac, protocol) via a different index → deduped
					"neighbor_mac": "aa:bb:cc:dd:ee:01", "protocol": "LLDP",
					"local_port": "11",
				},
			},
			{
				Source: "active:bridge_mib", Kind: "neighbor", IP: "192.168.2.10",
				RawData: map[string]string{
					"neighbor_mac": "aa:bb:cc:dd:ee:02", "protocol": "Bridge-MIB",
					"local_port": "eth0.1",
				},
			},
			{
				Source: "active:arp", Kind: "mac", IP: "192.168.2.10",
				RawData: map[string]string{"mac": "aa:bb:cc:dd:ee:10"},
			},
			{
				Source: "active:lldp_mib", Kind: "neighbor", IP: "192.168.2.10",
				RawData: map[string]string{"protocol": "LLDP"}, // no MAC → skipped
			},
		},
	}

	out := hostToReported(rep)

	require.Len(t, out.Neighbors, 2)
	require.Equal(t, "aa:bb:cc:dd:ee:01", out.Neighbors[0].NeighborMAC)
	require.Equal(t, "LLDP", out.Neighbors[0].Protocol)
	require.Equal(t, "10", out.Neighbors[0].LocalPort)
	require.Equal(t, "swp1", out.Neighbors[0].RemotePort)
	require.Equal(t, "sw-core", out.Neighbors[0].SysName)
	require.Equal(t, "Juniper EX4300", out.Neighbors[0].SysDesc)
	require.Equal(t, "active:lldp_mib", out.Neighbors[0].Source)
	require.Equal(t, "aa:bb:cc:dd:ee:02", out.Neighbors[1].NeighborMAC)
	require.Equal(t, "Bridge-MIB", out.Neighbors[1].Protocol)
	require.Equal(t, "eth0.1", out.Neighbors[1].LocalPort)
}
