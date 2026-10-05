package runner

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
)

// TestReportedHostToReport_MapsFieldsAndMAC verifies the wire payload →
// HostReport conversion carries every field the device bridge reads, and that
// the MAC is normalized and emitted as both a Field and a "mac" evidence piece
// (so reportMAC's fallback path resolves it).
func TestReportedHostToReport_MapsFieldsAndMAC(t *testing.T) {
	in := domain.ReportedHost{
		IP:               "192.168.2.41",
		Alive:            true,
		RTTMs:            12,
		MAC:              "AA-BB-CC-DD-EE-41",
		InferredType:     "camera",
		InferredBrand:    "hikvision",
		InferredLocation: "lobby",
		Hostname:         "cam-41",
		OpenPorts:        `[{"port":554,"service":"rtsp"}]`,
		Services: []domain.ReportedService{
			{Service: "rtsp", Port: 554, Protocol: "tcp"},
		},
		Heartbeats: []domain.ReportedHeartbeat{
			{Method: "tcp", Target: "192.168.2.41:554", IntervalSeconds: 30},
		},
	}

	rep := ReportedHostToReport(in)

	require.Equal(t, "192.168.2.41", rep.IP)
	require.True(t, rep.Alive)
	require.Equal(t, int64(12), rep.RTTMs)
	// Fields the bridge reads:
	require.Equal(t, "camera", rep.Device.Fields["inferred_type"])
	require.Equal(t, "hikvision", rep.Device.Fields["inferred_brand"])
	require.Equal(t, "lobby", rep.Device.Fields["inferred_location"])
	require.Equal(t, "cam-41", rep.Device.Fields["node_hostname"])
	require.Equal(t, `[{"port":554,"service":"rtsp"}]`, rep.Device.Fields["open_ports"])
	// MAC normalized to colon form in Fields:
	require.Equal(t, "aa:bb:cc:dd:ee:41", rep.Device.Fields["mac"])
	// And emitted as a normalized "mac" evidence piece (reportMAC fallback):
	require.Len(t, rep.Evidence, 1)
	require.Equal(t, "mac", rep.Evidence[0].Kind)
	require.Equal(t, "aa:bb:cc:dd:ee:41", rep.Evidence[0].RawData["mac"])
	// Services + heartbeats rebuilt:
	require.Len(t, rep.Services, 1)
	require.Equal(t, "rtsp", rep.Services[0].Service)
	require.Len(t, rep.Heartbeats, 1)
	require.Equal(t, "tcp", rep.Heartbeats[0].Method)
}

// TestReportedHostToReport_NoMACOmitsEvidence confirms a MAC-less host produces
// no mac evidence (so the bridge falls through to (ip, network_id) identity).
func TestReportedHostToReport_NoMACOmitsEvidence(t *testing.T) {
	rep := ReportedHostToReport(domain.ReportedHost{IP: "10.0.0.1", Alive: true})
	require.Empty(t, rep.Evidence)
	require.Empty(t, rep.Device.Fields["mac"])
}

// TestReportedHostToReport_NeighborsRebuildEvidence verifies the wire
// neighbors array becomes "neighbor"-kind evidence (the shape
// extractNeighbors + RecordNeighbors and the identity inference consume),
// with MAC normalization, optional-field omission, and row dropping for
// MAC-less or protocol-less entries.
func TestReportedHostToReport_NeighborsRebuildEvidence(t *testing.T) {
	in := domain.ReportedHost{
		IP:    "192.168.2.10",
		Alive: true,
		Neighbors: []domain.ReportedNeighbor{
			{
				NeighborMAC: "AA-BB-CC-DD-EE-01",
				Protocol:    "LLDP",
				LocalPort:   "ge-0/0/1",
				RemotePort:  "swp1",
				SysName:     "sw-core",
				SysDesc:     "Juniper EX4300",
				Source:      "active:lldp_mib",
			},
			{
				NeighborMAC: "aa:bb:cc:dd:ee:02",
				Protocol:    "Q-BRIDGE-MIB",
				LocalPort:   "2",
				VLANTag:     "30",
			},
			{NeighborMAC: "", Protocol: "LLDP"}, // no MAC → dropped
			{NeighborMAC: "aa:bb:cc:dd:ee:03"},  // no protocol → dropped
		},
	}

	rep := ReportedHostToReport(in)

	var neighbors []scannerv2.Evidence
	for _, e := range rep.Evidence {
		if e.Kind == "neighbor" {
			neighbors = append(neighbors, e)
		}
	}
	require.Len(t, neighbors, 2)

	n1 := neighbors[0]
	require.Equal(t, "active:lldp_mib", n1.Source)
	require.Equal(t, "aa:bb:cc:dd:ee:01", n1.RawData["neighbor_mac"])
	require.Equal(t, "LLDP", n1.RawData["protocol"])
	require.Equal(t, "ge-0/0/1", n1.RawData["local_port"])
	require.Equal(t, "swp1", n1.RawData["remote_port"])
	require.Equal(t, "sw-core", n1.RawData["sys_name"])
	require.Equal(t, "Juniper EX4300", n1.RawData["sys_desc"])
	// absent optional keys are simply not present (extractNeighbors reads ""
	// the same either way, but the shape mirrors a local scan's evidence)
	_, hasVLAN := n1.RawData["vlan_tag"]
	require.False(t, hasVLAN)

	n2 := neighbors[1]
	require.Equal(t, "agent", n2.Source) // empty Source defaults to "agent"
	require.Equal(t, "aa:bb:cc:dd:ee:02", n2.RawData["neighbor_mac"])
	require.Equal(t, "30", n2.RawData["vlan_tag"])
}
