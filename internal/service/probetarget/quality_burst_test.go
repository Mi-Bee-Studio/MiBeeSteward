// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"encoding/json"
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

// seedProbeRows creates one probe target and inserts one row per status rune
// ("s"/"f"/"t"), attaching the given burst metrics per row. optionsJSON carries
// the target's option block ("" = none) — the burst-target detector reads the
// TARGET's options, not the rows, so a burst target with a clean 0% round
// still counts toward the mean.
func seedProbeRows(t *testing.T, queries *db.Queries, name, module, target, vantage, optionsJSON, statuses string, loss, jitter []float64) {
	t.Helper()
	ctx := context.Background()
	created, err := queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
		Name: name, Module: module, Target: target,
		IntervalSeconds: 120, TimeoutSeconds: 5, Enabled: 1,
		Vantage: vantage, Source: domain.ProbeSourceSystem, Options: optionsJSON,
	})
	if err != nil {
		// Idempotent per name: reuse the existing row.
		prev, gerr := queries.GetProbeTargetByName(ctx, name)
		require.NoError(t, gerr)
		created.ID = prev.ID
	}
	require.Len(t, loss, len(statuses))
	require.Len(t, jitter, len(statuses))
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
			TargetID:  created.ID,
			Status:    st,
			LatencyMs: 50,
			CheckedAt: checked,
			Vantage:   vantage,
			LossPct:   loss[i],
			JitterMs:  jitter[i],
		}))
	}
}

// setupQualityCfg is setupQuality with a caller-supplied quality config —
// the verdict chain walks the SERVICE's config groups, so burst-matrix tests
// must hand in the config that carries the icmp leg.
func setupQualityCfg(t *testing.T, cfg config.ProbeQualityConfig) (*QualityService, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewQualityService(queries, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return svc, queries
}

// burstTestConfig is the quality matrix with one icmp burst leg added to the
// primary group — the #744 verdict surface.
func burstTestConfig() config.ProbeQualityConfig {
	cfg := testQualityConfig()
	cfg.Groups["domestic"] = append(cfg.Groups["domestic"], config.ProbeQualityTarget{
		Name: "q-ping", Module: "icmp", Target: "192.0.2.10",
	})
	return cfg
}

// TestQualityBurstStats pins the aggregation contract: a burst target's
// loss_pct/jitter_ms average over EVERY window row of that target (0% rounds
// included — excluding them would bias the mean upward), non-burst targets
// never contribute even if a stray row carries values.
func TestQualityBurstStats(t *testing.T) {
	svc, queries := setupQualityCfg(t, burstTestConfig())
	cfg := burstTestConfig()
	// Burst rows: loss 0,0,20,40 → mean 15; jitter 10,10,10,100 → mean 32.5.
	seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "center",
		`{"burst_count":10}`, "ssss",
		[]float64{0, 0, 20, 40}, []float64{10, 10, 10, 100})
	// Keep the rest of the matrix healthy so the burst leg is the only
	// reason source.
	seedQualityWorld(t, queries, cfg, "center", map[string]string{
		"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
	}, 50)

	report, err := svc.Analyze(context.Background(), 15)
	require.NoError(t, err)
	var col *QualityTargetMatrix
	for _, cat := range report.Categories {
		if cat.Category != ProbeCategoryQuality {
			continue
		}
		for _, g := range cat.Groups {
			for i, c := range g.Targets {
				if c.Name == "q-ping" {
					col = &g.Targets[i]
				}
			}
		}
	}
	require.NotNil(t, col, "burst target in matrix")
	st := col.PerVantage["center"]
	require.InDelta(t, 15.0, st.LossPct, 0.01, "mean includes the 0%% rounds")
	require.InDelta(t, 32.5, st.JitterMs, 0.01)
}

// TestQualityBurstVerdicts: burst metrics degrade the vantage with the
// STABLE CODES loss_burst / jitter_high; a non-burst target's stray metric
// row must NOT degrade anything.
func TestQualityBurstVerdicts(t *testing.T) {
	t.Run("loss_burst fires over threshold", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "center",
			`{"burst_count":10}`, "ssss",
			[]float64{0, 0, 20, 40}, []float64{2, 2, 2, 2})
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictDegraded, v.Verdict)
		require.Contains(t, v.Reasons, "loss_burst")
		require.NotContains(t, v.Reasons, "jitter_high")
	})
	t.Run("jitter_high fires over threshold", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "center",
			`{"burst_count":10}`, "ssss",
			[]float64{0, 0, 0, 0}, []float64{10, 10, 10, 100})
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictDegraded, v.Verdict)
		require.Contains(t, v.Reasons, "jitter_high")
		require.NotContains(t, v.Reasons, "loss_burst")
	})
	t.Run("under-threshold burst stays ok", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "center",
			`{"burst_count":10}`, "ssss",
			[]float64{0, 1, 0, 2}, []float64{5, 5, 5, 5})
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictOK, v.Verdict)
	})
	t.Run("non-burst target never contributes", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		// q-direct is a plain tcp target: stray loss/jitter values on its rows
		// (defensive — nothing writes them today) must be ignored.
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictOK, v.Verdict)
		require.NotContains(t, v.Reasons, "loss_burst")
		require.NotContains(t, v.Reasons, "jitter_high")
	})
}

// TestQualityUDPEgressAttribution pins the #745 attribution: every icmp leg
// dead while TCP-reachable legs still pass = UDP-path problem, not offline.
// The code is an ATTRIBUTION — it rides a degraded verdict, never mints one
// on its own (alert only on impact).
func TestQualityUDPEgressAttribution(t *testing.T) {
	t.Run("udp dead tcp alive", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "center",
			`{"burst_count":10}`, "tttt", []float64{0, 0, 0, 0}, []float64{0, 0, 0, 0})
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictDegraded, v.Verdict, "dead icmp legs drag ok-rate under threshold")
		require.Contains(t, v.Reasons, "udp_egress_blocked.tcp_alive_udp_dead")
	})
	t.Run("everything dead is egress_down, not udp attribution", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ffff", "q-dns-b": "ffff", "q-http": "ffff", "q-direct": "ffff", "q-int-http": "ssss",
		}, 50)
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "center",
			`{"burst_count":10}`, "tttt", []float64{0, 0, 0, 0}, []float64{0, 0, 0, 0})
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictEgressDown, v.Verdict)
		require.NotContains(t, v.Reasons, "udp_egress_blocked.tcp_alive_udp_dead")
	})
	t.Run("healthy network no code", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "center",
			`{"burst_count":10}`, "ssss", []float64{0, 0, 0, 0}, []float64{2, 2, 2, 2})
		v := primaryVerdict(t, svc, "center")
		require.Equal(t, QualityVerdictOK, v.Verdict)
	})
}

// TestQualityHostnetAttribution pins the #746 attribution: a degraded
// vantage whose agent reports rising interface error counters (or a default-
// route change) gains the stable evidence codes; a healthy vantage and a
// vantage with flat counters gain nothing.
func TestQualityHostnetAttribution(t *testing.T) {
	seedHostnet := func(t *testing.T, queries *db.Queries, vantage, route string, rxErrorsNewest, rxErrorsOlder float64) {
		t.Helper()
		ctx := context.Background()
		iface := func(rx float64) string {
			b, _ := json.Marshal(map[string]map[string]float64{
				"eth0": {"rx_errors": rx, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0},
			})
			return string(b)
		}
		newer := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
		older := time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
		require.NoError(t, queries.InsertVantageHostnet(ctx, db.InsertVantageHostnetParams{
			Vantage: vantage, CheckedAt: older, IfaceStats: iface(rxErrorsOlder),
			DefaultRoute: route, DnsMs: 5,
		}))
		require.NoError(t, queries.InsertVantageHostnet(ctx, db.InsertVantageHostnetParams{
			Vantage: vantage, CheckedAt: newer, IfaceStats: iface(rxErrorsNewest),
			DefaultRoute: route, DnsMs: 5,
		}))
	}
	t.Run("rising iface errors corroborate degradation", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		// The agent vantage's burst target degrades (loss over threshold).
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "agent:lan-42",
			`{"burst_count":10}`, "ssss",
			[]float64{0, 0, 20, 40}, []float64{2, 2, 2, 2})
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		seedHostnet(t, queries, "agent:lan-42", "eth0|192.0.2.1", 9500, 12)
		report, err := svc.Analyze(context.Background(), 15)
		require.NoError(t, err)
		found := false
		for _, cat := range report.Categories {
			for _, g := range cat.Groups {
				for _, v := range g.Vantages {
					if v.Vantage != "agent:lan-42" {
						continue
					}
					require.Equal(t, QualityVerdictDegraded, v.Verdict)
					require.Contains(t, v.Reasons, "vantage_local_degraded.iface_errors")
					found = true
				}
			}
		}
		require.True(t, found, "agent vantage verdict evaluated")
	})
	t.Run("route change corroborates degradation", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedProbeRows(t, queries, "q-ping", "icmp", "192.0.2.10", "agent:lan-42",
			`{"burst_count":10}`, "ssss",
			[]float64{0, 0, 20, 40}, []float64{2, 2, 2, 2})
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		// Same flat counters, but the default route moved between samples.
		seedHostnet(t, queries, "agent:lan-42", "eth0|192.0.2.1", 12, 12)
		seedHostnetRouteChange(t, queries, "agent:lan-42")
		report, err := svc.Analyze(context.Background(), 15)
		require.NoError(t, err)
		for _, cat := range report.Categories {
			for _, g := range cat.Groups {
				for _, v := range g.Vantages {
					if v.Vantage == "agent:lan-42" {
						require.Contains(t, v.Reasons, "vantage_local_degraded.route_change")
					}
				}
			}
		}
	})
	t.Run("healthy vantage gains nothing", func(t *testing.T) {
		svc, queries := setupQualityCfg(t, burstTestConfig())
		cfg := burstTestConfig()
		seedQualityWorld(t, queries, cfg, "center", map[string]string{
			"q-dns-a": "ssss", "q-dns-b": "ssss", "q-http": "ssss", "q-direct": "ssss", "q-int-http": "ssss",
		}, 50)
		seedHostnet(t, queries, "center", "eth0|192.0.2.1", 12, 12)
		report, err := svc.Analyze(context.Background(), 15)
		require.NoError(t, err)
		for _, cat := range report.Categories {
			for _, v := range cat.Vantages {
				require.NotContains(t, v.Reasons, "vantage_local_degraded.iface_errors")
				require.NotContains(t, v.Reasons, "vantage_local_degraded.route_change")
			}
		}
	})
}

// seedHostnetRouteChange overwrites the route fingerprint on the newest
// sample only — a route event without counter movement.
func seedHostnetRouteChange(t *testing.T, queries *db.Queries, vantage string) {
	t.Helper()
	ctx := context.Background()
	iface, _ := json.Marshal(map[string]map[string]float64{
		"eth0": {"rx_errors": 12, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0},
	})
	newer := time.Now().UTC().Add(-30 * time.Second).Format(time.RFC3339)
	require.NoError(t, queries.InsertVantageHostnet(ctx, db.InsertVantageHostnetParams{
		Vantage: vantage, CheckedAt: newer, IfaceStats: string(iface),
		DefaultRoute: "eth0|198.51.100.1", DnsMs: 5,
	}))
}

// TestQualityUDPEgressAttributionSimple pins the same attribution on the
// lan/external simple category (judgeSimpleCategory), where there is no
// egress chain — an external icmp target dead while an external tcp target
// passes reads as UDP-path trouble on that category's verdict.
func TestQualityUDPEgressAttributionSimple(t *testing.T) {
	svc, queries := setupQuality(t)
	ctx := context.Background()
	mk := func(name, module, target string) int64 {
		created, err := queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
			Name: name, Module: module, Target: target,
			IntervalSeconds: 120, TimeoutSeconds: 5, Enabled: 1,
			Vantage: domain.ProbeVantageCenter, Source: domain.ProbeSourceManual,
		})
		require.NoError(t, err)
		return created.ID
	}
	ping := mk("ext-ping", "icmp", "192.0.2.99")
	tcp := mk("ext-tcp", "tcp", "198.51.100.20:443")
	for i := 0; i < 4; i++ {
		checked := time.Now().UTC().Add(-time.Duration(i+1) * time.Minute).Format(time.RFC3339)
		require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{TargetID: ping, Status: "timeout", CheckedAt: checked, Vantage: domain.ProbeVantageCenter}))
		require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{TargetID: tcp, Status: "success", LatencyMs: 30, CheckedAt: checked, Vantage: domain.ProbeVantageCenter}))
	}
	report, err := svc.Analyze(context.Background(), 15)
	require.NoError(t, err)
	found := false
	for _, cat := range report.Categories {
		if cat.Category != ProbeCategoryExternal {
			continue
		}
		for _, v := range cat.Vantages {
			require.Equal(t, QualityVerdictDegraded, v.Verdict)
			require.Contains(t, v.Reasons, "udp_egress_blocked.tcp_alive_udp_dead")
			found = true
		}
	}
	require.True(t, found, "external category verdict evaluated")
}
