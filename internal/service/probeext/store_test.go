// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "probe_ext.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestStoreEgressRoundTrip pins the egress round persistence and the
// LatestEgress aggregation: per-source rows of the newest round, distinct
// public IPs with their window stats, and the synthetic local row.
func TestStoreEgressRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	older := now.Add(-time.Hour).Format(time.RFC3339)
	newer := now.Format(time.RFC3339)

	rows := []EgressRow{
		{Vantage: "center", RoundAt: older, Source: "http-a", Kind: "http", OK: true, IP: "203.0.113.9", ASN: "64496", ASName: "Example One", MS: 90},
		{Vantage: "center", RoundAt: older, Source: "stun-b", Kind: "stun", OK: true, IP: "203.0.113.9", MS: 40},
		{Vantage: "center", RoundAt: older, Source: "http-dead", Kind: "http", OK: false, Err: "i/o timeout"},
		{Vantage: "center", RoundAt: older, Source: "local", Kind: "local", OK: true, IP: "192.0.2.1", Err: "eth0"},
		{Vantage: "center", RoundAt: newer, Source: "http-a", Kind: "http", OK: true, IP: "203.0.113.10", MS: 95},
		{Vantage: "center", RoundAt: newer, Source: "http-dead", Kind: "http", OK: true, IP: "203.0.113.9", MS: 110},
		{Vantage: "center", RoundAt: newer, Source: "local", Kind: "local", OK: true, IP: "192.0.2.1", Err: "eth0"},
	}
	if err := store.InsertEgressRound(ctx, rows); err != nil {
		t.Fatalf("insert: %v", err)
	}

	views, err := store.LatestEgress(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if len(views) != 1 || views[0].Vantage != "center" {
		t.Fatalf("views = %+v", views)
	}
	v := views[0]
	if v.RoundAt != newer {
		t.Errorf("RoundAt = %q, want the newer round", v.RoundAt)
	}
	if v.LocalGateway != "192.0.2.1" || v.LocalIface != "eth0" {
		t.Errorf("local = %q/%q, want 192.0.2.1/eth0", v.LocalGateway, v.LocalIface)
	}
	if len(v.Sources) != 2 { // local row excluded
		t.Fatalf("sources = %+v", v.Sources)
	}
	byIP := map[string]EgressIPView{}
	for _, ip := range v.IPs {
		byIP[ip.IP] = ip
	}
	// Latest round observed BOTH IPs; the older round's 203.0.113.9 sighting
	// must fold into its window stats.
	if len(byIP) != 2 {
		t.Fatalf("ips = %+v", v.IPs)
	}
	if got := byIP["203.0.113.10"]; got.Samples != 1 || got.ASN != "" || len(got.Sources) != 1 || got.Sources[0] != "http-a" {
		t.Errorf("203.0.113.10 = %+v", got)
	}
	if got := byIP["203.0.113.9"]; got.Samples != 3 || got.ASN != "64496" || got.ASName != "Example One" {
		t.Errorf("203.0.113.9 = %+v (want 3 samples + ASN from the older row)", got)
	}
}

// TestStorePathRoundTrip pins path-sample persistence and the latest-per-
// (target, vantage) selection.
func TestStorePathRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	mk := func(targetID int64, name, vantage, end string, reached int) PathSample {
		return PathSample{
			TargetID: targetID, TargetName: name, Vantage: vantage,
			ResolvedIP: "192.0.2.7", Method: "tcp", EndState: end,
			ReachedTTL: reached, VisibleHops: 2,
			Hops:    []PathHop{{TTL: 1, IP: "192.0.2.1", MS: 0.5}, {TTL: 2}, {TTL: 3, IP: "192.0.2.7", MS: 2}},
			Trigger: "baseline", TracedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	if _, err := store.InsertPathSample(ctx, mk(1, "a", "center", "max_ttl", 0)); err != nil {
		t.Fatal(err)
	}
	latest := mk(1, "a", "center", "reached", 3)
	idNew, err := store.InsertPathSample(ctx, latest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.InsertPathSample(ctx, mk(2, "b", "center", "reached", 2)); err != nil {
		t.Fatal(err)
	}

	paths, err := store.LatestPaths(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("latest paths = %+v", paths)
	}
	for _, p := range paths {
		if p.TargetID == 1 && p.ID != idNew {
			t.Errorf("target 1 latest = %d, want %d (the reached sample)", p.ID, idNew)
		}
	}
	hist, err := store.ListPathsByTarget(ctx, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[0].ID != idNew {
		t.Fatalf("history order = %+v", hist)
	}
	// Prune removes both tables' old rows.
	if err := store.Prune(ctx, time.Now().UTC().Add(time.Minute).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if left, _ := store.LatestPaths(ctx, ""); len(left) != 0 {
		t.Errorf("prune left %d path samples", len(left))
	}
}
