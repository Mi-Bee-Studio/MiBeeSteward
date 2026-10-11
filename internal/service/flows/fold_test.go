// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package flows

import (
	"net/netip"
	"testing"

	"mibee-steward/internal/service/scannerv2/ebpf"
)

func lan() []netip.Prefix {
	return mustPrefixes("192.0.2.0/24")
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			panic(err)
		}
		out = append(out, p)
	}
	return out
}

func TestFoldEmpty(t *testing.T) {
	if got := Fold(nil, lan()); got != nil {
		t.Fatalf("Fold(nil) = %v, want nil", got)
	}
	if got := Fold([]ebpf.FlowSample{{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Bytes: 10}}, nil); got != nil {
		t.Fatalf("Fold with no prefixes = %v, want nil (nothing managed)", got)
	}
}

func TestFoldLanLanBothDirections(t *testing.T) {
	// One conversation seen in both directions (two map keys) folds into
	// two device records with mirrored out/in.
	got := Fold([]ebpf.FlowSample{
		{SrcIP: "192.0.2.10", DstIP: "192.0.2.20", Proto: 6, Dport: 443, Bytes: 100, Packets: 2},
		{SrcIP: "192.0.2.20", DstIP: "192.0.2.10", Proto: 6, Dport: 50000, Bytes: 40, Packets: 1},
	}, lan())
	want := []Agg{
		{DeviceIP: "192.0.2.10", PeerIP: "192.0.2.20", BytesOut: 100, BytesIn: 40},
		{DeviceIP: "192.0.2.20", PeerIP: "192.0.2.10", BytesOut: 40, BytesIn: 100},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Fold = %+v, want %+v", got, want)
	}
}

func TestFoldExternalPeer(t *testing.T) {
	got := Fold([]ebpf.FlowSample{
		{SrcIP: "192.0.2.10", DstIP: "198.51.100.9", Proto: 17, Dport: 53, Bytes: 75},
		{SrcIP: "203.0.113.7", DstIP: "192.0.2.10", Proto: 6, Dport: 22, Bytes: 500},
	}, lan())
	want := []Agg{
		{DeviceIP: "192.0.2.10", PeerIP: "198.51.100.9", BytesOut: 75},
		{DeviceIP: "192.0.2.10", PeerIP: "203.0.113.7", BytesIn: 500},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Fold = %+v, want %+v", got, want)
	}
}

func TestFoldMergesDuplicatesAndDropsTransit(t *testing.T) {
	got := Fold([]ebpf.FlowSample{
		{SrcIP: "192.0.2.10", DstIP: "192.0.2.20", Bytes: 10},
		{SrcIP: "192.0.2.10", DstIP: "192.0.2.20", Proto: 6, Dport: 80, Bytes: 15},
		// transit: neither endpoint managed
		{SrcIP: "198.51.100.1", DstIP: "203.0.113.1", Bytes: 999},
		// unparsable endpoint: corrupt data, dropped whole (a garbage peer
		// must never reach storage)
		{SrcIP: "192.0.2.30", DstIP: "not-an-ip", Bytes: 5},
	}, lan())
	want := []Agg{
		{DeviceIP: "192.0.2.10", PeerIP: "192.0.2.20", BytesOut: 25},
		{DeviceIP: "192.0.2.20", PeerIP: "192.0.2.10", BytesIn: 25},
	}
	if len(got) != len(want) {
		t.Fatalf("Fold = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Fold[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestFoldMultiplePrefixes(t *testing.T) {
	// Two managed subnets: cross-subnet traffic is LAN↔LAN (both records).
	got := Fold([]ebpf.FlowSample{
		{SrcIP: "192.0.2.1", DstIP: "198.18.0.5", Bytes: 30},
	}, mustPrefixes("192.0.2.0/24", "198.18.0.0/24"))
	if len(got) != 2 {
		t.Fatalf("Fold = %+v, want 2 records", got)
	}
	if got[0].BytesOut != 30 || got[1].BytesIn != 30 {
		t.Fatalf("cross-subnet fold = %+v", got)
	}
}
