// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package listenwatch

import (
	"testing"
)

const sampleTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 54321 1 0000000000000000 100 0 0 10 0
   2: 00000000:9C4A C0A83F09:B3D 01 00000000:00000000 02:00000095 00000000     0        0 66666 2 0000000000000000 21 4 30 10 -1
   3: FFFF:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77777 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNet(t *testing.T) {
	got := ParseProcNet(sampleTCP, "tcp")
	// 0x1538 = 5432 on 127.0.0.1 (0100007F), 0x16 = 22 on 0.0.0.0,
	// 0x50 = 80 on 255.255.0.0-ish word "FFFF" (defensive but well-formed);
	// the ESTABLISHED row (st 01) is skipped.
	if len(got) != 3 {
		t.Fatalf("parsed %d entries, want 3: %+v", len(got), got)
	}
	byPort := map[int]Entry{}
	for _, e := range got {
		byPort[e.Port] = e
	}
	if e := byPort[5432]; e.Addr != "0100007F" || e.Proto != "tcp" {
		t.Fatalf("5432 entry = %+v", e)
	}
	if e := byPort[22]; e.Addr != "00000000" {
		t.Fatalf("22 entry = %+v", e)
	}
	if e := byPort[80]; e.Port != 80 {
		t.Fatalf("80 entry = %+v", e)
	}
	if ParseProcNet("", "tcp") != nil {
		t.Fatal("empty input must yield nil")
	}
	if got := ParseProcNet("garbage line\n0A not enough\n", "tcp"); got != nil {
		t.Fatalf("malformed input = %+v", got)
	}
}

func TestDiff(t *testing.T) {
	prev := []Entry{
		{Proto: "tcp", Addr: "00000000", Port: 22},
		{Proto: "tcp", Addr: "0100007F", Port: 5432},
	}
	cur := []Entry{
		{Proto: "tcp", Addr: "00000000", Port: 22},     // unchanged
		{Proto: "tcp", Addr: "0100007F", Port: 5432},   // unchanged
		{Proto: "tcp", Addr: "00000000", Port: 8080},   // NEW
		{Proto: "tcp6", Addr: "00000000000000000000000000000000", Port: 9090}, // NEW (v6)
	}
	got := Diff(prev, cur)
	if len(got) != 2 {
		t.Fatalf("diff = %+v, want the 2 new entries", got)
	}
	if got[0].Port != 8080 || got[1].Port != 9090 || got[1].Proto != "tcp6" {
		t.Fatalf("diff = %+v", got)
	}
	if Diff(cur, cur) != nil {
		t.Fatal("no-change diff must be nil")
	}
	if Diff(prev, nil) != nil {
		t.Fatal("empty current must be nil")
	}
}

func TestDottedBind(t *testing.T) {
	if got := dottedBind(Entry{Proto: "tcp", Addr: "00000000", Port: 22}); got != "0.0.0.0" {
		t.Fatalf("v4 wildcard = %q", got)
	}
	if got := dottedBind(Entry{Proto: "tcp", Addr: "0100007F", Port: 1}); got != "127.0.0.1" {
		t.Fatalf("v4 loopback = %q", got)
	}
	// :: is 32 zero hex chars; a v6 loopback ::1 is ...01000000 in the last word.
	if got := dottedBind(Entry{Proto: "tcp6", Addr: "00000000000000000000000001000000", Port: 1}); got != "::1" {
		t.Fatalf("v6 loopback = %q", got)
	}
	if got := dottedBind(Entry{Proto: "tcp", Addr: "ZZ"}); got != "ZZ" {
		t.Fatalf("odd length falls back verbatim, got %q", got)
	}
}
