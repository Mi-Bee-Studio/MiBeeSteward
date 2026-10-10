// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package snmptrap

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

func addr(s string) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(s), Port: 63309}
}

func TestV2CTrapToEvidence(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: "public",
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1200)},
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.OctetString, Value: []byte{0x2b, 6, 1, 6, 3, 1, 1, 5, 3}}, // linkDown
			{Name: ".1.3.6.1.2.1.2.2.1.1.3", Type: gosnmp.Integer, Value: 3},                                          // ifIndex = 3
			{Name: ".1.3.6.1.2.1.2.2.1.8.3", Type: gosnmp.Integer, Value: 2},                                          // ifOperStatus.3 = down
		},
	}
	ev := evidenceFromTrap(pkt, addr("192.0.2.9"))
	if ev.Source != "passive:snmp-trap" || ev.Kind != "snmp_trap" {
		t.Fatalf("Source/Kind = %q/%q", ev.Source, ev.Kind)
	}
	if ev.IP != "192.0.2.9" || ev.Protocol != "udp" {
		t.Fatalf("IP/Protocol = %q/%q", ev.IP, ev.Protocol)
	}
	if ev.RawData["trap"] != "linkDown" {
		t.Errorf("trap = %q, want linkDown", ev.RawData["trap"])
	}
	if ev.RawData["if_index"] != "3" {
		t.Errorf("if_index = %q", ev.RawData["if_index"])
	}
	if ev.RawData["if_oper_status"] != "down" {
		t.Errorf("if_oper_status = %q, want down", ev.RawData["if_oper_status"])
	}
	if ev.Confidence != 0.9 {
		t.Errorf("confidence = %v", ev.Confidence)
	}
}

func TestV1GenericTrapToEvidence(t *testing.T) {
	// v1 generic trap 3 = linkUp, carrying agent address and uptime.
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version1,
		SnmpTrap: gosnmp.SnmpTrap{
			Enterprise:   ".1.3.6.1.4.1.8072",
			AgentAddress: "192.0.2.9",
			GenericTrap:  3,
			SpecificTrap: 0,
			Timestamp:    42,
		},
	}
	ev := evidenceFromTrap(pkt, addr("192.0.2.9"))
	if ev.RawData["trap"] != "linkUp" {
		t.Fatalf("trap = %q, want linkUp (v1 generic 3)", ev.RawData["trap"])
	}
	if ev.RawData["snmp_version"] != "1" {
		t.Errorf("snmp_version = %q", ev.RawData["snmp_version"])
	}
}

func TestV1EnterpriseSpecificTrap(t *testing.T) {
	pkt := &gosnmp.SnmpPacket{
		Version: gosnmp.Version1,
		SnmpTrap: gosnmp.SnmpTrap{
			Enterprise:   ".1.3.6.1.4.1.9",
			GenericTrap:  6, // enterpriseSpecific
			SpecificTrap: 1,
		},
	}
	ev := evidenceFromTrap(pkt, addr("192.0.2.10"))
	if ev.RawData["trap"] != "enterpriseSpecific" {
		t.Fatalf("trap = %q", ev.RawData["trap"])
	}
	if ev.RawData["enterprise"] != "1.3.6.1.4.1.9" || ev.RawData["specific"] != "1" {
		t.Errorf("enterprise/specific = %q/%q", ev.RawData["enterprise"], ev.RawData["specific"])
	}
}

func TestThrottleCollapsesFlappingStorm(t *testing.T) {
	th := newThrottle(50 * time.Millisecond)
	key := trapKey("192.0.2.9", "linkDown")
	if !th.allow(key) {
		t.Fatal("first occurrence must pass")
	}
	if th.allow(key) {
		t.Fatal("immediate repeat must be throttled")
	}
	// A different trap from the same device passes: different key.
	if !th.allow(trapKey("192.0.2.9", "coldStart")) {
		t.Fatal("different trap type must pass")
	}
	time.Sleep(60 * time.Millisecond)
	if !th.allow(key) {
		t.Fatal("after the window the same trap passes again")
	}
}

// End-to-end over the wire: a real gosnmp client sends a v2c trap to the
// receiver's listener; the evidence lands in the store, the wrong community is
// dropped by the listener (never reaches the store).
func TestListenerReceivesV2CTrap(t *testing.T) {
	store := &memStore{}
	r := New(Config{Bind: "127.0.0.1:11620", Community: "public"}, store, nil)
	if err := r.Start(); err != nil {
		t.Skipf("cannot bind test port: %v", err)
	}
	defer r.Stop()
	<-r.Listening()

	send := func(community string) error {
		c := &gosnmp.GoSNMP{
			Target:          "127.0.0.1",
			Port:            11620,
			Version:         gosnmp.Version2c,
			Community:       community,
			Timeout:         2 * time.Second,
			MaxOids:         gosnmp.MaxOids,
			Retries:         0,
			ExponentialTimeout: false,
		}
		if err := c.Connect(); err != nil {
			return err
		}
		defer c.Conn.Close()
		_, err := c.SendTrap(gosnmp.SnmpTrap{
			Variables: []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1)},
				{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.OctetString, Value: []byte{0x2b, 6, 1, 6, 3, 1, 1, 5, 1}}, // coldStart
			},
		})
		return err
	}
	if err := send("wrong-community"); err != nil {
		t.Fatalf("send with wrong community: %v", err)
	}
	if err := send("public"); err != nil {
		t.Fatalf("send with right community: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for len(store.evs) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(store.evs) != 1 {
		t.Fatalf("stored %d evidence rows, want exactly 1 (wrong community dropped): %+v", len(store.evs), store.evs)
	}
	ev := store.evs[0]
	if ev.IP != "127.0.0.1" || ev.RawData["trap"] != "coldStart" {
		t.Fatalf("evidence = %+v", ev)
	}
}

type memStore struct {
	mu  sync.Mutex
	evs []scannerv2.Evidence
}

func (m *memStore) RecordEvidence(_ context.Context, evs []scannerv2.Evidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evs = append(m.evs, evs...)
	return nil
}
