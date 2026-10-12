// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// fakeSnmp scripts an SNMP agent for the MIB walkers: Walk answers every OID
// prefix with its configured PDUs (in order), Get answers with a fixed packet.
// Injected by swapping dialSNMP (restored by the deferred helper).
type fakeSnmp struct {
	walks map[string][]gosnmp.SnmpPDU // OID prefix → scripted varbinds
	get   *gosnmp.SnmpPacket          // scripted Get reply
	// optional failures
	walkErrs map[string]error
	getErr   error
	connErr  error
	closed   bool
}

func (f *fakeSnmp) Walk(oid string, fn gosnmp.WalkFunc) error {
	if err, ok := f.walkErrs[oid]; ok {
		return err
	}
	for _, pdu := range f.walks[oid] {
		if err := fn(pdu); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeSnmp) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.get != nil {
		return f.get, nil
	}
	vars := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		vars = append(vars, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.Null, Value: nil})
	}
	return &gosnmp.SnmpPacket{Variables: vars}, nil
}

func (f *fakeSnmp) Close() error { f.closed = true; return nil }

// pdu builds a walk varbind: Name = "." + prefix + "." + index (gosnmp's
// convention for Walk results).
func pdu(prefix, index string, typ gosnmp.Asn1BER, value any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: "." + prefix + "." + index, Type: typ, Value: value}
}

// injectFakeSnmp swaps dialSNMP to always return the fake (any ip/version) and
// restores the real dialer on test cleanup. Returns the fake for mutation.
func injectFakeSnmp(t *testing.T, f *fakeSnmp) *fakeSnmp {
	t.Helper()
	if f == nil {
		f = &fakeSnmp{}
	}
	prevDial := dialSNMP
	dialSNMP = func(_ string, _ scannerv2.ProbeHint, _ gosnmp.SnmpVersion, _ int) (snmpClient, error) {
		if f.connErr != nil {
			return nil, f.connErr
		}
		return f, nil
	}
	t.Cleanup(func() { dialSNMP = prevDial })
	return f
}

func probeHint() scannerv2.ProbeHint {
	return scannerv2.ProbeHint{Timeout: 1e9} // 1s: unused by the fake
}

// --- LLDP-MIB ---

func TestLLDPMIBProbe_WalkScripted(t *testing.T) {
	idx := "0.5.1" // timeMark.localPort.remIndex
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidLldpRemChassisSub: {pdu(oidLldpRemChassisSub, idx, gosnmp.Integer, 4)},
		oidLldpRemChassisID:  {pdu(oidLldpRemChassisID, idx, gosnmp.OctetString, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})},
		oidLldpRemPortID:     {pdu(oidLldpRemPortID, idx, gosnmp.OctetString, []byte("eth0"))},
		oidLldpRemSysName:    {pdu(oidLldpRemSysName, idx, gosnmp.OctetString, "core-sw")},
		oidLldpRemSysDesc:    {pdu(oidLldpRemSysDesc, idx, gosnmp.OctetString, "Cisco IOS")},
	}})

	evs, err := NewLLDPMIBProbe(nil).Probe(context.Background(), "10.1.1.1", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 1)
	rd := evs[0].RawData
	require.Equal(t, "aa:bb:cc:dd:ee:ff", rd["neighbor_mac"])
	require.Equal(t, "LLDP", rd["protocol"])
	require.Equal(t, "5", rd["local_port"])
	require.Equal(t, "eth0", rd["remote_port"])
	require.Equal(t, "core-sw", rd["sys_name"])

	// A chassis subtype without a MAC merge key (7 = locally assigned) yields
	// no evidence, un-joinable edges are skipped by design.
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidLldpRemChassisSub: {pdu(oidLldpRemChassisSub, idx, gosnmp.Integer, 7)},
		oidLldpRemChassisID:  {pdu(oidLldpRemChassisID, idx, gosnmp.OctetString, []byte("not-a-mac"))},
	}})
	evs, err = NewLLDPMIBProbe(nil).Probe(context.Background(), "10.1.1.1", probeHint())
	require.NoError(t, err)
	require.Empty(t, evs)
}

// --- CDP-MIB ---

func TestCDPMIBProbe_WalkScripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidCDPDeviceID:   {pdu(oidCDPDeviceID, "5", gosnmp.OctetString, "SW-CORE-01")},
		oidCDPAddress:    {pdu(oidCDPAddress, "5", gosnmp.OctetString, []byte{0x01, 0x06, 0xcc, 0x04, 0xc0, 0xa8, 0x01, 0x01})},
		oidCDPVersion:    {pdu(oidCDPVersion, "5", gosnmp.OctetString, "IOS 15.2")},
		oidCDPDevicePort: {pdu(oidCDPDevicePort, "5", gosnmp.OctetString, "GigabitEthernet0/2")},
		oidCDPPlatform:   {pdu(oidCDPPlatform, "5", gosnmp.OctetString, "cisco WS-C2960")},
		oidIfNameCDP:     {pdu(oidIfNameCDP, "5", gosnmp.OctetString, "GigabitEthernet0/5")},
	}})

	evs, err := NewCDPMIBProbe(nil).Probe(context.Background(), "10.2.2.2", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 1)
	rd := evs[0].RawData
	require.Equal(t, "SW-CORE-01", rd["neighbor_mac"], "CDP Device ID is the merge key")
	require.Equal(t, "CDP", rd["protocol"])
	require.Equal(t, "GigabitEthernet0/5", rd["local_port"], "ifName resolution overrides numeric ifIndex")
	require.Equal(t, "GigabitEthernet0/2", rd["remote_port"])
	require.Equal(t, "192.168.1.1", rd["neighbor_ip"])
	require.Equal(t, "cisco WS-C2960", rd["platform"])
	require.Equal(t, "IOS 15.2", rd["version"])

	// No CDP cache at all → no evidence (the densest column drives the loop).
	injectFakeSnmp(t, &fakeSnmp{})
	evs, err = NewCDPMIBProbe(nil).Probe(context.Background(), "10.2.2.2", probeHint())
	require.NoError(t, err)
	require.Empty(t, evs)
}

// --- Q-BRIDGE-MIB ---

func TestQBridgeMIBProbe_WalkScripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidDot1qVlanStaticName: {
			pdu(oidDot1qVlanStaticName, "42", gosnmp.OctetString, "mgmt"),
			pdu(oidDot1qVlanStaticName, "100", gosnmp.OctetString, "voice"),
		},
		oidDot1qTpFdbPort: {
			// VLAN 100, MAC 10.0.1.2.3.4 (0a:00:01:02:03:04) on bridge port 3.
			pdu(oidDot1qTpFdbPort, "100.10.0.1.2.3.4", gosnmp.Integer, 3),
		},
		oidDot1dBasePortIfIndex: {pdu(oidDot1dBasePortIfIndex, "3", gosnmp.Integer, 103)},
		oidIfName:               {pdu(oidIfName, "103", gosnmp.OctetString, "ge-0/0/3")},
	}})

	evs, err := NewQBridgeMIBProbe(nil).Probe(context.Background(), "10.3.3.3", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 3, "two named VLANs + one FDB neighbor")

	kinds := map[string]scannerv2.Evidence{}
	for _, e := range evs {
		kinds[e.Kind] = e
	}
	vlan, ok := kinds["vlan"]
	require.True(t, ok, "vlan evidence expected")
	require.Contains(t, []string{"mgmt", "voice"}, vlan.RawData["vlan_name"])
	require.Contains(t, []string{"42", "100"}, vlan.RawData["vlan_tag"])
	neighbor, ok := kinds["neighbor"]
	require.True(t, ok, "neighbor evidence expected")
	require.Equal(t, "0a:00:01:02:03:04", neighbor.RawData["neighbor_mac"])
	require.Equal(t, "ge-0/0/3", neighbor.RawData["local_port"])
	require.Equal(t, "100", neighbor.RawData["vlan_tag"])

	// Neither static VLANs nor FDB → no evidence.
	injectFakeSnmp(t, &fakeSnmp{})
	evs, err = NewQBridgeMIBProbe(nil).Probe(context.Background(), "10.3.3.3", probeHint())
	require.NoError(t, err)
	require.Empty(t, evs)
}

// --- STP-MIB ---

func TestSTPMIBProbe_WalkScripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidDot1dStpPortDesignatedBridge: {
			// Port 1 sees designated bridge 0x8000 + aa:bb:cc:dd:ee:ff.
			pdu(oidDot1dStpPortDesignatedBridge, "1", gosnmp.OctetString,
				[]byte{0x80, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}),
		},
		oidDot1dBasePortIfIndex: {pdu(oidDot1dBasePortIfIndex, "1", gosnmp.Integer, 11)},
		oidIfName:               {pdu(oidIfName, "11", gosnmp.OctetString, "port11")},
	}, get: &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
		{Name: "." + oidDot1dBaseBridgeAddress, Type: gosnmp.OctetString, Value: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}},
	}}})

	evs, err := NewSTPMIBProbe(nil).Probe(context.Background(), "10.4.4.4", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 1)
	rd := evs[0].RawData
	require.Equal(t, "aa:bb:cc:dd:ee:ff", rd["neighbor_mac"])
	require.Equal(t, "STP", rd["protocol"])
	require.Equal(t, "port11", rd["local_port"])

	// Get failure (no bridge address) → no evidence.
	injectFakeSnmp(t, &fakeSnmp{getErr: errors.New("timeout")})
	evs, err = NewSTPMIBProbe(nil).Probe(context.Background(), "10.4.4.4", probeHint())
	require.NoError(t, err)
	require.Empty(t, evs)
}

// --- STP-MIB port roles + root bridge (#525) ---

// The extended walk collects dot1dStpPortRole and dot1dStpDesignatedRoot on
// top of the designated-bridge edges: the neighbor evidence gains a
// port_role key, and a device-level "stp" evidence carries the root facts
// (own bridge MAC, root bridge MAC, is_root, per-port roles) that fold into
// scan_attributes.stp.
func TestSTPMIBProbe_RolesAndRoot(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidDot1dStpPortDesignatedBridge: {
			// Port 1 (toward the root) sees designated bridge aa:bb:cc:dd:ee:ff.
			pdu(oidDot1dStpPortDesignatedBridge, "1", gosnmp.OctetString,
				[]byte{0x80, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}),
			// Port 2's designated bridge is the local switch itself: edge skipped.
			pdu(oidDot1dStpPortDesignatedBridge, "2", gosnmp.OctetString,
				[]byte{0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
		},
		oidDot1dStpPortRole: {
			pdu(oidDot1dStpPortRole, "1", gosnmp.Integer, 4), // root
			pdu(oidDot1dStpPortRole, "2", gosnmp.Integer, 5), // designated
		},
		oidDot1dBasePortIfIndex: {pdu(oidDot1dBasePortIfIndex, "1", gosnmp.Integer, 11)},
		oidIfName:               {pdu(oidIfName, "11", gosnmp.OctetString, "port11")},
	}, get: &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
		{Name: "." + oidDot1dBaseBridgeAddress, Type: gosnmp.OctetString, Value: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}},
		{Name: "." + oidDot1dStpDesignatedRoot, Type: gosnmp.OctetString, Value: []byte{0x80, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
	}}})

	evs, err := NewSTPMIBProbe(nil).Probe(context.Background(), "10.4.4.4", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 2, "one device-level stp evidence + one neighbor edge")

	var stp, neighbor scannerv2.Evidence
	for _, e := range evs {
		switch e.Kind {
		case "stp":
			stp = e
		case "neighbor":
			neighbor = e
		}
	}
	require.NotNil(t, stp.RawData, "device-level stp evidence must be present")
	require.Equal(t, "11:22:33:44:55:66", stp.RawData["bridge_mac"])
	require.Equal(t, "aa:bb:cc:dd:ee:ff", stp.RawData["root_bridge_mac"])
	require.Equal(t, "false", stp.RawData["is_root"])
	require.Equal(t, "port11=root,2=designated", stp.RawData["ports"],
		"roles keyed by resolved ifName when known, bridge port otherwise")

	require.Equal(t, "aa:bb:cc:dd:ee:ff", neighbor.RawData["neighbor_mac"])
	require.Equal(t, "root", neighbor.RawData["port_role"],
		"the edge toward the designated root carries its STP role")
}

// The root bridge itself: every designated bridge is the local switch (all
// edges self-skip), but the root facts still land — this is exactly the
// device the graph needs to mark as root.
func TestSTPMIBProbe_RootBridgeNoEdges(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidDot1dStpPortDesignatedBridge: {
			pdu(oidDot1dStpPortDesignatedBridge, "1", gosnmp.OctetString,
				[]byte{0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
		},
		oidDot1dStpPortRole: {
			pdu(oidDot1dStpPortRole, "1", gosnmp.Integer, 5), // designated
		},
	}, get: &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
		{Name: "." + oidDot1dBaseBridgeAddress, Type: gosnmp.OctetString, Value: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}},
		{Name: "." + oidDot1dStpDesignatedRoot, Type: gosnmp.OctetString, Value: []byte{0x80, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}},
	}}})

	evs, err := NewSTPMIBProbe(nil).Probe(context.Background(), "10.4.4.4", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 1, "no neighbor edges, but the stp evidence survives")
	require.Equal(t, "stp", evs[0].Kind)
	require.Equal(t, "true", evs[0].RawData["is_root"])
	require.Equal(t, "11:22:33:44:55:66", evs[0].RawData["root_bridge_mac"])
}

// --- IF-MIB interface census (#529) ---

func TestIFMIBProbe_WalkScripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidIfNameX: {
			// wire shape: gosnmp decodes real agents' OCTET STRINGs to []byte
			pdu(oidIfNameX, "1", gosnmp.OctetString, []byte("eth0")),
			pdu(oidIfNameX, "2", gosnmp.OctetString, []byte("eth1")),
		},
		oidIfDescr: {
			pdu(oidIfDescr, "1", gosnmp.OctetString, []byte("Ethernet0")),
			pdu(oidIfDescr, "3", gosnmp.OctetString, []byte("lo0")),
		},
		oidIfPhysAddr: {
			pdu(oidIfPhysAddr, "1", gosnmp.OctetString, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
		},
		oidIfSpeed: {
			pdu(oidIfSpeed, "1", gosnmp.Gauge32, 1_000_000_000),
		},
		oidIPAdEntIdx: {
			pdu(oidIPAdEntIdx, "192.168.1.1", gosnmp.Integer, 1),
			pdu(oidIPAdEntIdx, "10.0.5.1", gosnmp.Integer, 2),
		},
	}})

	evs, err := NewIFMIBProbe(nil).Probe(context.Background(), "10.6.6.6", probeHint())
	require.NoError(t, err)
	// eth0 (mac + ip), eth1 (ip only), lo0 (neither -> skipped).
	require.Len(t, evs, 2)
	byIndex := map[string]scannerv2.Evidence{}
	for _, e := range evs {
		byIndex[e.RawData["if_index"]] = e
	}
	eth0 := byIndex["1"]
	require.Equal(t, "eth0", eth0.RawData["if_name"])
	require.Equal(t, "aa:bb:cc:dd:ee:01", eth0.RawData["mac"])
	require.Equal(t, "192.168.1.1", eth0.RawData["ip"])
	require.Equal(t, "1000", eth0.RawData["speed_mbps"])
	eth1 := byIndex["2"]
	require.Equal(t, "10.0.5.1", eth1.RawData["ip"])
	require.Equal(t, "eth1", eth1.RawData["if_name"])
	require.Empty(t, eth1.RawData["mac"], "no ifPhysAddress row renders empty")
}

// --- Route-MIB ipRouteTable (#528) ---

func TestRouteMIBProbe_WalkScripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidIPRouteDest: {
			// Key = the dest IP's dotted-octet index.
			pdu(oidIPRouteDest, "0.0.0.0", gosnmp.OctetString, []byte{0, 0, 0, 0}),
			pdu(oidIPRouteDest, "172.16.0.0", gosnmp.OctetString, []byte{172, 16, 0, 0}),
			pdu(oidIPRouteDest, "192.168.50.0", gosnmp.OctetString, []byte{192, 168, 50, 0}),
		},
		oidIPRouteNextHop: {
			pdu(oidIPRouteNextHop, "0.0.0.0", gosnmp.OctetString, []byte{10, 0, 0, 254}),
			pdu(oidIPRouteNextHop, "172.16.0.0", gosnmp.OctetString, []byte{10, 0, 0, 254}),
			// Direct route: next hop 0.0.0.0 -> skipped.
			pdu(oidIPRouteNextHop, "192.168.50.0", gosnmp.OctetString, []byte{0, 0, 0, 0}),
		},
		oidIPRouteType: {
			pdu(oidIPRouteType, "0.0.0.0", gosnmp.Integer, 4),
			pdu(oidIPRouteType, "172.16.0.0", gosnmp.Integer, 4),
			pdu(oidIPRouteType, "192.168.50.0", gosnmp.Integer, 3),
		},
		oidIPRouteProto: {
			pdu(oidIPRouteProto, "0.0.0.0", gosnmp.Integer, 3),     // netmgmt
			pdu(oidIPRouteProto, "172.16.0.0", gosnmp.Integer, 11), // ospf
		},
		oidIPRouteMask: {
			pdu(oidIPRouteMask, "0.0.0.0", gosnmp.OctetString, []byte{0, 0, 0, 0}),
			pdu(oidIPRouteMask, "172.16.0.0", gosnmp.OctetString, []byte{255, 255, 0, 0}),
		},
		oidIPRouteIfIndex: {
			pdu(oidIPRouteIfIndex, "0.0.0.0", gosnmp.Integer, 2),
			pdu(oidIPRouteIfIndex, "172.16.0.0", gosnmp.Integer, 2),
		},
	}})

	evs, err := NewRouteMIBProbe(nil).Probe(context.Background(), "10.7.7.7", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 2, "direct route skipped, two indirect routes emitted")

	var def, corp scannerv2.Evidence
	for _, e := range evs {
		if e.RawData["dest"] == "0.0.0.0/0" {
			def = e
		} else {
			corp = e
		}
	}
	require.Equal(t, "10.0.0.254", def.RawData["next_hop"])
	require.Equal(t, "2", def.RawData["if_index"])
	require.Equal(t, "172.16.0.0/16", corp.RawData["dest"], "mask renders as prefix length")
	require.Equal(t, "11", corp.RawData["proto"])
}

// --- Bridge-MIB ---

func TestBridgeMIBProbe_WalkScripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidDot1dTpFdbPort: {
			pdu(oidDot1dTpFdbPort, "170.187.204.221.238.255", gosnmp.Integer, 2),
		},
		oidDot1dBasePortIfIndex: {pdu(oidDot1dBasePortIfIndex, "2", gosnmp.Integer, 22)},
		oidIfName:               {pdu(oidIfName, "22", gosnmp.OctetString, "fe-1")},
	}})

	evs, err := NewBridgeMIBProbe(nil).Probe(context.Background(), "10.5.5.5", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 1)
	rd := evs[0].RawData
	require.Equal(t, "aa:bb:cc:dd:ee:ff", rd["neighbor_mac"])
	require.Equal(t, "Bridge-MIB", rd["protocol"])
	require.Equal(t, "fe-1", rd["local_port"])

	// Empty FDB → no evidence.
	injectFakeSnmp(t, &fakeSnmp{})
	evs, err = NewBridgeMIBProbe(nil).Probe(context.Background(), "10.5.5.5", probeHint())
	require.NoError(t, err)
	require.Empty(t, evs)
}

// --- Router ARP walk (snmp_arp) ---

func TestWalkRouterARPTableHint_Scripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidIPNetToMediaPhysAddress: {
			pdu(oidIPNetToMediaPhysAddress, "2.192.168.1.133", gosnmp.OctetString,
				[]byte{0xbc, 0xad, 0x28, 0x11, 0x22, 0x33}),
		},
	}})

	table, err := walkRouterARPTableHint("10.6.6.6", probeHint(), 1)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"192.168.1.133": "bc:ad:28:11:22:33"}, table)

	// Legacy table empty → the RFC 4293 fallback is consulted.
	injectFakeSnmp(t, &fakeSnmp{walks: map[string][]gosnmp.SnmpPDU{
		oidIPNetToPhysicalAddress: {
			pdu(oidIPNetToPhysicalAddress, "2.4.192.168.1.134", gosnmp.OctetString,
				[]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}),
		},
	}})
	table, err = walkRouterARPTableHint("10.6.6.6", probeHint(), 1)
	require.NoError(t, err)
	require.NotEmpty(t, table)

	// Connect failure shows up as an error (the caller logs WHY a router
	// yields nothing, unlike the probes, this distinguishes unreachable).
	f := injectFakeSnmp(t, nil)
	f.connErr = errors.New("no route")
	_, err = walkRouterARPTableHint("10.6.6.6", probeHint(), 1)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "no route") || strings.Contains(err.Error(), "snmp connect"))
}

// --- snmpGetOnce (the 8-OID system Get) ---

func TestSnmpGetOnce_Scripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{get: &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("Linux 6.1 router")},
		{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("core-gw")},
	}}})

	raw, ok := snmpGetOnce("10.7.7.7", probeHint(), gosnmp.Version2c)
	require.True(t, ok)
	require.Contains(t, raw, "sys_descr")
	require.Contains(t, raw, "sys_name")

	// Get error → not-ok, no panic.
	f := injectFakeSnmp(t, nil)
	f.getErr = errors.New("timeout")
	_, ok = snmpGetOnce("10.7.7.7", probeHint(), gosnmp.Version2c)
	require.False(t, ok)
}

// --- router-ARP public surface (cache-backed lookups) ---

func TestRouterARPLookups_CachedAndScripted(t *testing.T) {
	walks := map[string][]gosnmp.SnmpPDU{
		oidIPNetToMediaPhysAddress: {
			pdu(oidIPNetToMediaPhysAddress, "2.192.168.1.133", gosnmp.OctetString,
				[]byte{0xbc, 0xad, 0x28, 0x11, 0x22, 0x33}),
		},
	}
	calls := 0
	prevDial := dialSNMP
	dialSNMP = func(_ string, _ scannerv2.ProbeHint, _ gosnmp.SnmpVersion, _ int) (snmpClient, error) {
		calls++
		return &fakeSnmp{walks: walks}, nil
	}
	t.Cleanup(func() { dialSNMP = prevDial })
	// Fresh cache per test (the global is keyed to a single router).
	routerARPCacheGlobal = routerARPStore{}
	t.Cleanup(func() { routerARPCacheGlobal = routerARPStore{} })

	ctx := context.Background()

	// The walk returns the full table.
	table := WalkRouterARPTable(ctx, "10.8.8.8", "public", time.Second)
	require.Equal(t, map[string]string{"192.168.1.133": "bc:ad:28:11:22:33"}, table)

	// Observable variant returns the same map + nil error.
	table2, err := WalkRouterARPTableWithErr(ctx, "10.8.8.8", "public", time.Second)
	require.NoError(t, err)
	require.Equal(t, table, table2)

	// Lookup hits the cached walk (no extra dial).
	mac, ok := LookupMACViaRouter(ctx, "10.8.8.8", "public", time.Second, "192.168.1.133")
	require.True(t, ok)
	require.Equal(t, "bc:ad:28:11:22:33", mac)
	callsAfterLookup := calls

	_, ok = LookupMACViaRouter(ctx, "10.8.8.8", "public", time.Second, "192.168.1.1")
	require.False(t, ok, "unknown ip → miss")
	require.Equal(t, callsAfterLookup, calls, "cache must absorb repeat lookups for the same router/community")

	// Router list wrapper: first router that knows the ip wins.
	mac, ok = LookupMACViaRouters(ctx, RouterARPConfig{
		Routers: []string{"10.8.8.8"}, Timeout: time.Second,
	}, "192.168.1.133")
	require.True(t, ok)
	require.Equal(t, "bc:ad:28:11:22:33", mac)

	// Credential-aware path: v1v2c credential keyed by its id.
	cred := &scannerv2.SNMPCredential{ID: 5, SecurityLevel: scannerv2.SNMPLevelV1V2C, Community: "public"}
	mac, ok = LookupMACViaRouterCred(ctx, "10.8.8.9", cred, time.Second, "192.168.1.133")
	require.True(t, ok)
	require.Equal(t, "bc:ad:28:11:22:33", mac)

	// Empty router string short-circuits to nil.
	require.Nil(t, routerARPCacheGlobal.get(ctx, "", "public", time.Second))
}

func TestCredKeyBuilders(t *testing.T) {
	require.Equal(t, "public", credKeyForCommunity(""))
	require.Equal(t, "private", credKeyForCommunity("private"))

	require.Equal(t, "cred:5:snmpadmin",
		credKeyForCredential(&scannerv2.SNMPCredential{ID: 5, UserName: "snmpadmin"}))
	require.Equal(t, "ad-hoc:core:op",
		credKeyForCredential(&scannerv2.SNMPCredential{Name: "core", UserName: "op"}))
}

// TestSNMPProbe_ProbeScripted drives the full 8-OID system probe through the
// fake: v2c answers on the first ladder rung, varbinds land in Evidence
// RawData, and the version + uptime normalization are applied.
func TestSNMPProbe_ProbeScripted(t *testing.T) {
	injectFakeSnmp(t, &fakeSnmp{get: &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte("Linux 6.1")},
		{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("edge-sw")},
	}}})

	evs, err := NewSNMPProbe().Probe(context.Background(), "10.7.7.8", probeHint())
	require.NoError(t, err)
	require.Len(t, evs, 1)
	e := evs[0]
	require.Equal(t, "active:snmp", e.Source)
	require.Equal(t, "snmp", e.Kind)
	require.Equal(t, "2c", e.RawData["snmp_version"])
	require.Equal(t, "Linux 6.1", e.RawData["sys_descr"])
	require.Equal(t, "edge-sw", e.RawData["sys_name"])

	// Nothing answers (Get errors on both ladder rungs) → no evidence, no error.
	f := injectFakeSnmp(t, nil)
	f.getErr = errors.New("timeout")
	evs, err = NewSNMPProbe().Probe(context.Background(), "10.7.7.8", probeHint())
	require.NoError(t, err)
	require.Empty(t, evs)
}
