// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//go:build !WITH_LLDP && !WITH_CDP && !WITH_ARPSCAN

package discovery

import "testing"

// Build-tag introspection (#502): the default build reports every optional
// frame/ARP capability as absent. The WITH_* companions (build_lldp_on_test.go
// and friends) assert the positive side under their own tags.
func TestOptionalTagsAbsentInDefaultBuild(t *testing.T) {
	if BuiltWithLLDP() {
		t.Fatal("BuiltWithLLDP() = true in the default build")
	}
	if BuiltWithCDP() {
		t.Fatal("BuiltWithCDP() = true in the default build")
	}
	if BuiltWithARPSCAN() {
		t.Fatal("BuiltWithARPSCAN() = true in the default build")
	}
}

func TestParseCapEffHex(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   uint64
		ok     bool
	}{
		{"root has everything", "CapInh:\t0000000000000000\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n", 0x1ffffffffff, true},
		{"net raw only", "CapEff:\t0000000000002000\n", 0x2000, true},
		{"absent", "CapInh:\t0000000000000000\n", 0, false},
		{"garbage", "CapEff:\tnot-hex\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseCapEffHex(c.status)
			if ok != c.ok || got != c.want {
				t.Fatalf("parseCapEffHex = (%#x, %v), want (%#x, %v)", got, ok, c.want, c.ok)
			}
		})
	}
}

// capNetRawPresent must hold for a CapEff with bit 13 set and fail for one
// without it — the single privilege all three optional sources need.
func TestCapNetRawPresent(t *testing.T) {
	for _, c := range []struct {
		name string
		caps uint64
		want bool
	}{
		{"bit 13 set", 1 << 13, true},
		{"root full set", 0x1ffffffffff, true},
		{"bit 13 clear", 0x1ffffffffff &^ (1 << 13), false},
		{"zero", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := capNetRawPresent(c.caps); got != c.want {
				t.Fatalf("capNetRawPresent(%#x) = %v, want %v", c.caps, got, c.want)
			}
		})
	}
}
