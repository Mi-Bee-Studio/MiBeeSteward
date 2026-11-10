// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"testing"
	"time"

	"mibee-steward/internal/domain"
)

// TestIngestAgentEgress pins the agent egress round ingest (#718): vantage
// stamped from the reporting agent (payload claims ignored), local row
// convention, and per-source rows with public-IP enrichment skipped for
// failures and non-public IPs.
func TestIngestAgentEgress(t *testing.T) {
	queries, _ := openTestQueries(t)
	store := openTestStore(t)
	cfg := testServiceCfg()
	// One resolver answering Cymru-shape TXT so the enrichment path runs
	// end-to-end offline: the origin query (asn|prefix|range|date) and the
	// AS-name query (6-field layout, name on index 5).
	dns := fakeDNSTXT(t, map[string]string{
		"10.216.184.93.origin.asn.cymru.com": "4134 | 1.2.3.0/24 | 1.2.3.0 - 1.2.3.255 | 2026-01-01",
		"as4134.asn.cymru.com":               "4134 | 1.2.3.0/24 | 1.2.3.0 - 1.2.3.255 | CN | 2026-01-01 | CHINANET-BACKBONE",
	})
	cfg.Egress.ASNResolvers = []string{dns}
	svc := NewService(cfg, store, queries, nil)
	ctx := context.Background()

	n, err := svc.IngestAgentEgress(ctx, "agent-62", []AgentEgressRound{{
		RoundAt: time.Now().UTC().Format(time.RFC3339),
		Local:   AgentEgressLocal{Iface: "end0", GatewayIP: "192.168.2.1", GatewayMAC: "aa:bb:cc:dd:ee:ff"},
		Results: []AgentEgressSourceResult{
			{Source: "icanhazip", Kind: "http", OK: true, IP: "93.184.216.10", MS: 120},
			{Source: "cf-trace", Kind: "http", OK: true, IP: "93.184.216.10", MS: 130}, // same IP: enriched once
			{Source: "stun-google", Kind: "stun", OK: false, Err: "no mapped address"},
		},
	}})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n != 1 {
		t.Fatalf("accepted = %d, want 1", n)
	}

	rows, err := store.LatestEgress(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var vants = map[string]bool{}
	for _, v := range rows {
		vants[v.Vantage] = true
	}
	if !vants[domain.ProbeVantageAgentPrefix+"agent-62"] {
		t.Fatalf("no agent-62 vantage in %v", vants)
	}

	// Row-level checks straight from the store.
	var local, src, asn, asName string
	if err := store.Conn().QueryRowContext(ctx,
		`SELECT source, err FROM egress_rounds WHERE source = 'local'`).Scan(&local, &src); err != nil {
		t.Fatal(err)
	}
	if local != "local" || src != "end0" {
		t.Fatalf("local row = %q / %q", local, src)
	}
	if err := store.Conn().QueryRowContext(ctx,
		`SELECT asn, as_name FROM egress_rounds WHERE source = 'icanhazip'`).Scan(&asn, &asName); err != nil {
		t.Fatal(err)
	}
	if asn != "4134" || asName != "CHINANET-BACKBONE" {
		t.Fatalf("asn enrichment = %q / %q", asn, asName)
	}
	// The failed source row is stored with ok=0 and no IP.
	var ok int
	var ip string
	if err := store.Conn().QueryRowContext(ctx,
		`SELECT ok, ip FROM egress_rounds WHERE source = 'stun-google'`).Scan(&ok, &ip); err != nil {
		t.Fatal(err)
	}
	if ok != 0 || ip != "" {
		t.Fatalf("failed row = ok:%d ip:%q", ok, ip)
	}
}

// TestIngestAgentPaths pins the agent path ingest (#719): vantage override,
// live target name (renames propagate), visible-hop recount, unknown-target
// skip, and the baseline default for an absent trigger.
func TestIngestAgentPaths(t *testing.T) {
	queries, conn := openTestQueries(t)
	insertTarget(t, conn, 7, "web", "http", "http://www.example.org/", "manual", true, nil)
	store := openTestStore(t)
	svc := NewService(testServiceCfg(), store, queries, nil)
	ctx := context.Background()

	n, err := svc.IngestAgentPaths(ctx, "agent-62", []AgentPathSample{
		{
			TargetID:   7,
			TargetName: "stale-name", // center re-derives from the live row
			ResolvedIP: "93.184.216.34", Method: "tcp", EndState: "reached",
			ReachedTTL: 3, ReplyTTL: 55,
			Hops:     []PathHop{{TTL: 1, IP: "192.168.2.1"}, {TTL: 2}, {TTL: 3, IP: "93.184.216.34"}},
			TracedAt: "2026-11-08T08:00:00Z",
		},
		{TargetID: 9999, EndState: "error", TracedAt: "2026-11-08T08:00:00Z"}, // unknown target: skipped
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n != 1 {
		t.Fatalf("accepted = %d, want 1", n)
	}

	rows, err := store.ListPathsByTarget(ctx, 7, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	got := rows[0]
	if got.Vantage != domain.ProbeVantageAgentPrefix+"agent-62" {
		t.Fatalf("vantage = %q", got.Vantage)
	}
	if got.TargetName != "web" {
		t.Fatalf("target_name = %q, want the live row's name", got.TargetName)
	}
	if got.VisibleHops != 2 {
		t.Fatalf("visible_hops = %d, want recounted 2", got.VisibleHops)
	}
	if got.Trigger != "baseline" {
		t.Fatalf("trigger = %q, want defaulted baseline", got.Trigger)
	}
	if got.ReplyTTL != 55 {
		t.Fatalf("reply_ttl = %d", got.ReplyTTL)
	}
}
