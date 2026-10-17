// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func testQualityConfig() config.ProbeQualityConfig {
	return config.ProbeQualityConfig{
		Enabled: true, WindowMinutes: 15, IntervalSeconds: 120,
		HTTPDegradedMs: 800, DNSDegradedMs: 300, OkRateThreshold: 0.9,
		Groups: map[string][]config.ProbeQualityTarget{
			"domestic": {
				{Name: "q-dns-a", Module: "dns", Target: "www.example.com", Options: map[string]any{"resolver": "203.0.113.53"}},
				{Name: "q-dns-b", Module: "dns", Target: "www.example.com", Options: map[string]any{"resolver": "198.51.100.53"}},
				{Name: "q-http", Module: "http", Target: "https://www.example.org/"},
				{Name: "q-direct", Module: "tcp", Target: "203.0.113.10:443"},
			},
			"international": {
				{Name: "q-int-http", Module: "http", Target: "https://www.example.net/"},
			},
		},
	}
}

func setupQuality(t *testing.T) (*QualityService, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewQualityService(queries, testQualityConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	return svc, queries
}

// TestQualitySeed pins the config→DB reconciliation (#608): create, be
// idempotent, refresh drift, delete removals, park on disabled.
func TestQualitySeed(t *testing.T) {
	svc, queries := setupQuality(t)
	ctx := context.Background()

	require.NoError(t, svc.Seed(ctx))
	names := map[string]db.ProbeTarget{}
	list, err := queries.ListProbeTargets(ctx)
	require.NoError(t, err)
	require.Len(t, list, 5, "4 domestic + 1 international")
	for _, tgt := range list {
		names[tgt.Name] = tgt
		require.Equal(t, domain.ProbeSourceSystem, tgt.Source)
		require.Equal(t, domain.ProbeVantageAll, tgt.Vantage)
		require.Equal(t, int64(1), tgt.Enabled)
	}
	direct := names["q-direct"]
	require.Equal(t, "tcp", direct.Module)
	dnsA := names["q-dns-a"]
	require.Contains(t, dnsA.Options, "203.0.113.53")

	// Idempotent: a second seed changes nothing.
	require.NoError(t, svc.Seed(ctx))
	list2, err := queries.ListProbeTargets(ctx)
	require.NoError(t, err)
	require.Len(t, list2, 5)

	// Drift: config edits the http target's URL → seed refreshes it.
	cfg := testQualityConfig()
	cfg.Groups["domestic"][2].Target = "https://www.example.org/healthz"
	svcDrift := NewQualityService(queries, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, svcDrift.Seed(ctx))
	refreshed, err := queries.GetProbeTargetByName(ctx, "q-http")
	require.NoError(t, err)
	require.Equal(t, "https://www.example.org/healthz", refreshed.Target)

	// Removal: a config entry deleted → the system row and its history go.
	cfg2 := testQualityConfig()
	cfg2.Groups["domestic"] = cfg2.Groups["domestic"][:3] // drop q-direct
	svcRemove := NewQualityService(queries, cfg2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, svcRemove.Seed(ctx))
	list3, err := queries.ListProbeTargets(ctx)
	require.NoError(t, err)
	require.Len(t, list3, 4)
	_, err = queries.GetProbeTargetByName(ctx, "q-direct")
	require.Error(t, err, "removed with the config entry")

	// Disabled: every system target is parked (disabled), not deleted.
	cfgOff := testQualityConfig()
	cfgOff.Enabled = false
	svcOff := NewQualityService(queries, cfgOff, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, svcOff.Seed(ctx))
	list4, err := queries.ListProbeTargets(ctx)
	require.NoError(t, err)
	require.Len(t, list4, 4, "parked, not deleted")
	for _, tgt := range list4 {
		require.Equal(t, int64(0), tgt.Enabled)
	}
}

// qualityWorld inserts the matrix rows + a pattern of results at one or more
// vantages. pattern maps target name → statuses ("s"/"f"/"t" per sample).
// Idempotent per name: the cross-vantage scenario seeds twice.
func seedQualityWorld(t *testing.T, queries *db.Queries, cfg config.ProbeQualityConfig, vantage string, pattern map[string]string, latency float64) {
	t.Helper()
	ctx := context.Background()
	for _, group := range cfg.Groups {
		for _, qt := range group {
			var id int64
			if prev, err := queries.GetProbeTargetByName(ctx, qt.Name); err == nil {
				id = prev.ID
			} else {
				created, cerr := queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
					Name: qt.Name, Module: qt.Module, Target: qt.Target,
					IntervalSeconds: 120, TimeoutSeconds: 5, Enabled: 1,
					Vantage: domain.ProbeVantageAll, Source: domain.ProbeSourceSystem,
				})
				require.NoError(t, cerr)
				id = created.ID
			}
			statuses, ok := pattern[qt.Name]
			if !ok {
				continue
			}
			for i, c := range statuses {
				st := "success"
				switch c {
				case 'f':
					st = "fail"
				case 't':
					st = "timeout"
				}
				checked := time.Now().UTC().Add(-time.Duration(i+1) * time.Minute).Format(time.RFC3339)
				require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
					TargetID: id, Status: st, LatencyMs: latency, CheckedAt: checked, Vantage: vantage,
				}))
			}
		}
	}
}

func primaryVerdict(t *testing.T, svc *QualityService, vantage string) QualityVantageReport {
	t.Helper()
	report, err := svc.Analyze(context.Background(), 15)
	require.NoError(t, err)
	for _, g := range report.Groups {
		if g.Role != "primary" {
			continue
		}
		for _, v := range g.Vantages {
			if v.Vantage == vantage {
				return v
			}
		}
	}
	t.Fatalf("no verdict for vantage %q", vantage)
	return QualityVantageReport{}
}

// TestQualityVerdictChain pins the deterministic verdict chain.
func TestQualityVerdictChain(t *testing.T) {
	all := func(statuses string) string { return statuses }

	t.Run("all healthy", func(t *testing.T) {
		svc, queries := setupQuality(t)
		seedQualityWorld(t, queries, testQualityConfig(), "center", map[string]string{
			"q-dns-a": all("ssss"), "q-dns-b": all("ssss"),
			"q-http": all("ssss"), "q-direct": all("ssss"), "q-int-http": all("ssss"),
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictOK, v.Verdict)
		require.Equal(t, 100, v.Score)
	})
	t.Run("egress down", func(t *testing.T) {
		svc, queries := setupQuality(t)
		seedQualityWorld(t, queries, testQualityConfig(), "center", map[string]string{
			"q-dns-a": all("ffff"), "q-dns-b": all("ffff"),
			"q-http": all("ffff"), "q-direct": all("ffff"), "q-int-http": all("ssss"),
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictEgressDown, v.Verdict)
		require.Contains(t, v.Reasons, "egress_down.all_paths_failing")
		require.LessOrEqual(t, v.Score, 25)
	})
	t.Run("dns fault: direct ok, names dead", func(t *testing.T) {
		svc, queries := setupQuality(t)
		seedQualityWorld(t, queries, testQualityConfig(), "center", map[string]string{
			"q-dns-a": all("ffff"), "q-dns-b": all("ffff"),
			"q-http": all("ffff"), "q-direct": all("ssss"), "q-int-http": all("ssss"),
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictDNSFault, v.Verdict)
	})
	t.Run("upstream resolver split", func(t *testing.T) {
		svc, queries := setupQuality(t)
		seedQualityWorld(t, queries, testQualityConfig(), "center", map[string]string{
			"q-dns-a": all("ssss"), "q-dns-b": all("ffff"),
			"q-http": all("ssss"), "q-direct": all("ssss"), "q-int-http": all("ssss"),
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictUpstreamResolver, v.Verdict)
		require.Contains(t, v.Reasons[0], "q-dns-b")
	})
	t.Run("degraded on latency", func(t *testing.T) {
		svc, queries := setupQuality(t)
		seedQualityWorld(t, queries, testQualityConfig(), "center", map[string]string{
			"q-dns-a": all("ssss"), "q-dns-b": all("ssss"),
			"q-http": all("ssss"), "q-direct": all("ssss"), "q-int-http": all("ssss"),
		}, 1200) // http p50 over the 800ms budget
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictDegraded, v.Verdict)
		require.Contains(t, v.Reasons, "latency_high")
	})
	t.Run("insufficient without data", func(t *testing.T) {
		svc, queries := setupQuality(t)
		seedQualityWorld(t, queries, testQualityConfig(), "center", map[string]string{}, 50)
		// No results → no vantage entries at all: the panel shows no-data
		// rather than a wrong verdict.
		report, err := svc.Analyze(context.Background(), 15)
		require.NoError(t, err)
		for _, g := range report.Groups {
			require.Empty(t, g.Vantages)
			for _, col := range g.Targets {
				require.Equal(t, "no_data", col.CrossVantage)
			}
		}
	})
	t.Run("cross-vantage isolation excludes a dead target", func(t *testing.T) {
		svc, queries := setupQuality(t)
		cfg := testQualityConfig()
		// q-http fails on BOTH vantages → target_down → excluded; everything
		// else healthy at center → center reads ok, agent reads ok too.
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ffff", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		seedQualityWorld(t, queries, cfg, "agent:lan-63", map[string]string{
			"q-http": "ffff", "q-direct": "ssss",
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictOK, v.Verdict)
		report, err := svc.Analyze(context.Background(), 15)
		require.NoError(t, err)
		for _, g := range report.Groups {
			for _, col := range g.Targets {
				if col.Name == "q-http" {
					require.Equal(t, "target_down", col.CrossVantage)
				}
			}
		}
	})
}
