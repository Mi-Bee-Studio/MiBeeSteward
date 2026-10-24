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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// seedBucket inserts `n` results for every config target at a fixed offset,
// with per-target statuses ("s"=success, "f"=fail) and success latency.
func seedBucket(t *testing.T, queries *db.Queries, vantage string, offset time.Duration, statuses map[string]string, latency float64) {
	t.Helper()
	ctx := context.Background()
	for name, pattern := range statuses {
		tgt, err := queries.GetProbeTargetByName(ctx, name)
		require.NoError(t, err, "seed bucket: target %s", name)
		for i := 0; i < len(pattern); i++ {
			st := "success"
			if pattern[i] == 'f' {
				st = "fail"
			}
			checked := time.Now().UTC().Add(-offset + time.Duration(i)*time.Second).Format(time.RFC3339)
			require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
				TargetID: tgt.ID, Status: st, LatencyMs: latency, CheckedAt: checked, Vantage: vantage,
			}))
		}
	}
}

func primarySeries(t *testing.T, svc *QualityService, days int, vantage string) QualityHistorySeries {
	t.Helper()
	report, err := svc.History(context.Background(), days)
	require.NoError(t, err)
	for _, g := range report.Groups {
		if g.Role != "primary" {
			continue
		}
		for _, s := range g.Series {
			if s.Vantage == vantage {
				return s
			}
		}
	}
	t.Fatalf("no primary series for vantage %s", vantage)
	return QualityHistorySeries{}
}

// TestQualityHistoryHourlyBuckets pins the 7-day shape: hourly buckets, one
// point per (vantage, hour) with data, ascending order, and the SAME verdict
// chain as the live window replayed per bucket.
func TestQualityHistoryHourlyBuckets(t *testing.T) {
	svc, queries := setupQuality(t)
	ctx := context.Background()
	require.NoError(t, svc.Seed(ctx))

	allOK := map[string]string{
		"q-dns-a": "sss", "q-dns-b": "sss", "q-http": "sss", "q-direct": "sss", "q-int-http": "sss",
	}
	// 3h ago: everything healthy. 1h ago: dns_fault shape (direct ok, both
	// resolvers + http dead) - two buckets, two different verdicts.
	seedBucket(t, queries, "center", 3*time.Hour, allOK, 50)
	seedBucket(t, queries, "center", 1*time.Hour, map[string]string{
		"q-dns-a": "fff", "q-dns-b": "fff", "q-http": "fff", "q-direct": "sss", "q-int-http": "sss",
	}, 50)

	report, err := svc.History(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, 7, report.Days)
	require.Equal(t, "hour", report.Bucket)
	require.NotEmpty(t, report.Groups)

	s := primarySeries(t, svc, 7, "center")
	require.Len(t, s.Points, 2)
	// Ascending bucket order; hour-prefixed timestamps.
	require.Less(t, s.Points[0].T, s.Points[1].T)
	require.Contains(t, s.Points[0].T, "T", "hour buckets carry the T-hour prefix")
	// 3h-ago bucket: all healthy.
	require.Equal(t, QualityVerdictOK, s.Points[0].Verdict)
	require.InDelta(t, 1.0, s.Points[0].OkRate, 1e-9)
	require.Equal(t, 100, s.Points[0].Score)
	require.InDelta(t, 50.0, s.Points[0].AvgMs, 1e-9)
	// 1h-ago bucket: the dns_fault shape replays exactly.
	require.Equal(t, QualityVerdictDNSFault, s.Points[1].Verdict)
	require.Less(t, s.Points[1].OkRate, 0.9)
	require.LessOrEqual(t, s.Points[1].Score, 25)
	// The primary (domestic) group evaluates its 4 legs; q-int-http lives in
	// the international reference group and never joins this series.
	require.Equal(t, 12, s.Points[1].Samples, "4 domestic legs x 3 samples")
}

// TestQualityHistoryRangeAndGranularity pins the range cutoff and the
// 7d→hour / 30d→day switch: an 8-day-old bucket is outside days=7 and shows
// up only in the 30-day daily view.
func TestQualityHistoryRangeAndGranularity(t *testing.T) {
	svc, queries := setupQuality(t)
	ctx := context.Background()
	require.NoError(t, svc.Seed(ctx))
	allOK := map[string]string{
		"q-dns-a": "s", "q-dns-b": "s", "q-http": "s", "q-direct": "s", "q-int-http": "s",
	}
	seedBucket(t, queries, "center", 8*24*time.Hour, allOK, 50)
	seedBucket(t, queries, "center", 3*24*time.Hour, allOK, 50)

	week := primarySeries(t, svc, 7, "center")
	require.Len(t, week.Points, 1, "the 8-day-old bucket is out of range")

	month, err := svc.History(ctx, 30)
	require.NoError(t, err)
	require.Equal(t, "day", month.Bucket)
	s := primarySeries(t, svc, 30, "center")
	require.Len(t, s.Points, 2, "both buckets at daily granularity")
	require.Equal(t, QualityVerdictOK, s.Points[0].Verdict)
}

// TestQualityHistoryTargetDownIsolation pins that the cross-vantage
// target-down exclusion applies PER BUCKET: a leg failing everywhere in one
// bucket is target-side there and does not drag that bucket's verdict, while
// the ok bucket stays ok.
func TestQualityHistoryTargetDownIsolation(t *testing.T) {
	svc, queries := setupQuality(t)
	ctx := context.Background()
	require.NoError(t, svc.Seed(ctx))
	others := map[string]string{"q-dns-a": "ss", "q-dns-b": "ss", "q-direct": "ss", "q-int-http": "ss"}
	// 2h ago: q-http fails from BOTH vantages -> target-down, excluded.
	seedBucket(t, queries, "center", 2*time.Hour, map[string]string{"q-http": "ff"}, 50)
	seedBucket(t, queries, "agent:edge-1", 2*time.Hour, map[string]string{"q-http": "ff"}, 50)
	seedBucket(t, queries, "center", 2*time.Hour, others, 50)

	s := primarySeries(t, svc, 7, "center")
	require.Len(t, s.Points, 1)
	require.Equal(t, QualityVerdictOK, s.Points[0].Verdict, "target-down leg excluded per bucket")
	require.Equal(t, 100, s.Points[0].Score)
}

// TestQualityHistorySkipsNonSystemTargets pins the SQL filter: only enabled
// source=system rows feed the trend.
func TestQualityHistorySkipsNonSystemTargets(t *testing.T) {
	svc, queries := setupQuality(t)
	ctx := context.Background()
	require.NoError(t, svc.Seed(ctx))
	manual, err := queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
		Name: "manual-http", Module: "http", Target: "https://www.example.com/",
		IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: 1, Vantage: "center",
		Source: domain.ProbeSourceManual,
	})
	require.NoError(t, err)
	require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
		TargetID: manual.ID, Status: "fail", LatencyMs: 0,
		CheckedAt: time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339), Vantage: "center",
	}))
	// Also park a system target and prove its rows are excluded too.
	parked, err := queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
		Name: "q-parked", Module: "http", Target: "https://parked.example.com/",
		IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: 0, Vantage: "all",
		Source: domain.ProbeSourceSystem,
	})
	require.NoError(t, err)
	require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
		TargetID: parked.ID, Status: "fail", LatencyMs: 0,
		CheckedAt: time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339), Vantage: "center",
	}))

	report, err := svc.History(ctx, 7)
	require.NoError(t, err)
	// Manual + parked rows never produce series points; the config groups'
	// names are the only ones referenced.
	for _, g := range report.Groups {
		for _, s := range g.Series {
			for _, p := range s.Points {
				require.NotEqual(t, QualityVerdictInsufficient, p.Verdict, "non-system rows must not create phantom buckets")
			}
		}
	}
}
