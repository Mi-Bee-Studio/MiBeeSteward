// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You should use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"database/sql"
	"testing"
)

// seedNetworks inserts network rows and returns their ids in insertion order.
func seedNetworks(t *testing.T, dbConn *sql.DB, rows ...[2]string) []int64 {
	t.Helper()
	var ids []int64
	for _, r := range rows {
		res, err := dbConn.Exec(`INSERT INTO networks (name, cidr) VALUES (?, ?)`, r[0], r[1])
		if err != nil {
			t.Fatalf("seed network %v: %v", r, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("last insert id: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

// The resolver is the data-driven half of passive-discovery attribution
// (#386): an IP lands in the network whose CIDR contains it, longest prefix
// wins, and anything unresolvable reports no match so the caller keeps its
// fallback (the center's own network).
func TestNetworkResolver_LongestPrefixAndFallback(t *testing.T) {
	dbConn := memoryDB(t)
	ids := seedNetworks(t, dbConn,
		[2]string{"supernet", "10.0.0.0/16"}, // id[0]
		[2]string{"lan-a", "10.0.0.0/24"},    // id[1]: more specific than the supernet
		[2]string{"lan-b", "10.0.1.0/24"},    // id[2]
		[2]string{"no-cidr", ""},             // skipped: containment impossible
		[2]string{"broken", "not-a-cidr"},    // skipped: invalid
	)
	r := NewNetworkResolver(dbConn)
	ctx := context.Background()

	for _, tc := range []struct {
		ip   string
		want int64 // 0 = no match
	}{
		{"10.0.0.5", ids[1]}, // /24 beats the overlapping /16
		{"10.0.1.5", ids[2]}, // the other /24
		{"10.0.5.5", ids[0]}, // inside the /16 only (outside both /24s)
		{"192.168.50.1", 0},  // outside every cidr → no match
		{"not-an-ip", 0},     // unparseable → no match
	} {
		got := r.Resolve(ctx, tc.ip)
		if tc.want == 0 {
			if got.Valid {
				t.Errorf("Resolve(%q) = %d, want no match", tc.ip, got.Int64)
			}
			continue
		}
		if !got.Valid || got.Int64 != tc.want {
			t.Errorf("Resolve(%q) = %v, want %d", tc.ip, got, tc.want)
		}
	}
}

// A nil resolver (agent wiring, minimal setups) must behave as "no match";
// the pre-#386 fallback path, never a panic.
func TestNetworkResolver_NilReceiverIsNoMatch(t *testing.T) {
	var r *NetworkResolver
	if got := r.Resolve(context.Background(), "10.0.0.1"); got.Valid {
		t.Errorf("nil resolver Resolve = %v, want no match", got)
	}
	if NewNetworkResolver(nil) != nil {
		t.Error("NewNetworkResolver(nil) should return nil")
	}
}

// Fresh rows steer attribution within one cache TTL: after inserting a new
// network and forcing the cache to expire, previously-unmatched IPs resolve
// to it. (Expiry is exercised via the internal loaded timestamp, so the test
// doesn't sleep for a full minute.)
func TestNetworkResolver_PicksUpNewRows(t *testing.T) {
	dbConn := memoryDB(t)
	r := NewNetworkResolver(dbConn)
	ctx := context.Background()

	if got := r.Resolve(ctx, "172.16.0.1"); got.Valid {
		t.Fatalf("expected no match before seeding, got %v", got)
	}
	ids := seedNetworks(t, dbConn, [2]string{"new-lan", "172.16.0.0/24"})
	r.mu.Lock()
	r.loaded = r.loaded.Add(-networkCacheTTL - 1) // force expiry
	r.mu.Unlock()

	got := r.Resolve(ctx, "172.16.0.1")
	if !got.Valid || got.Int64 != ids[0] {
		t.Errorf("after seeding + expiry, Resolve = %v, want %d", got, ids[0])
	}
}

// The gate answers whether a sighting may be attributed at all: matching a
// known CIDR resolves it; matching none while geometry exists flags it
// off-subnet (the caller drops it); no known geometry keeps the fallback.
func TestNetworkResolver_ResolveGate(t *testing.T) {
	ctx := context.Background()
	dbConn := memoryDB(t)
	ids := seedNetworks(t, dbConn, [2]string{"lan", "192.168.62.0/24"})
	r := NewNetworkResolver(dbConn)

	nid, anyKnown := r.ResolveGate(ctx, "192.168.62.40")
	if !nid.Valid || nid.Int64 != ids[0] {
		t.Fatalf("in-subnet IP must resolve to the network, got %+v", nid)
	}
	if !anyKnown {
		t.Fatal("geometry exists, anyKnown must be true")
	}

	nid, anyKnown = r.ResolveGate(ctx, "192.168.193.60") // WAN-arm style address
	if nid.Valid {
		t.Fatal("off-subnet IP must not resolve")
	}
	if !anyKnown {
		t.Fatal("geometry exists, anyKnown must be true so the caller can drop")
	}

	// No CIDRs configured anywhere: no gate, the fallback applies.
	empty := memoryDB(t)
	seedNetworks(t, empty, [2]string{"no-cidr", ""})
	r2 := NewNetworkResolver(empty)
	nid, anyKnown = r2.ResolveGate(ctx, "192.168.193.60")
	if nid.Valid || anyKnown {
		t.Fatalf("no geometry means no gate, got nid=%+v anyKnown=%v", nid, anyKnown)
	}
}
