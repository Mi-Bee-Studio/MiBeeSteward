// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// Quality-history trend (the /probe-quality/history endpoint): the SAME
// verdict chain and score as the live window, replayed per time bucket over
// the retention horizon. Buckets aggregate in SQL (ListProbeQualityBuckets)
// so the row stream stays tiny no matter how many raw results the range
// covers; the one approximation is latency: per-bucket budgets are judged
// against the bucket's mean success latency instead of an exact p50 (the
// structural verdicts - egress_down / dns_fault / upstream_resolver - are
// ok-rate driven and stay exact).

// QualityHistoryPoint is one bucket of one (group, vantage) series.
type QualityHistoryPoint struct {
	T       string  `json:"t"` // bucket start, RFC3339 UTC
	OkRate  float64 `json:"ok_rate"`
	AvgMs   float64 `json:"avg_ms"`
	Samples int     `json:"samples"`
	Score   int     `json:"score"`
	Verdict string  `json:"verdict"`
}

// QualityHistorySeries is one vantage's line within a group.
type QualityHistorySeries struct {
	Vantage     string                `json:"vantage"`
	NetworkName string                `json:"network_name,omitempty"`
	Points      []QualityHistoryPoint `json:"points"`
}

// QualityHistoryGroup mirrors QualityGroupReport's grouping (primary +
// reference config groups), carrying time series instead of matrices.
type QualityHistoryGroup struct {
	Name   string                 `json:"name"`
	Role   string                 `json:"role"` // primary | reference
	Series []QualityHistorySeries `json:"series"`
}

// QualityHistoryReport is the GET /api/v1/probe-quality/history payload.
type QualityHistoryReport struct {
	Days   int                   `json:"days"`
	Bucket string                `json:"bucket"` // hour | day
	Groups []QualityHistoryGroup `json:"groups"`
}

// History buckets the quality matrix's results over the last `days` days and
// replays the verdict chain per bucket. days<=7 buckets hourly, longer ranges
// daily - a 30-day chart at hourly resolution would be ~720 x-axis points,
// more noise than signal on a LAN monitor.
func (s *QualityService) History(ctx context.Context, days int) (QualityHistoryReport, error) {
	if days <= 0 {
		days = 7
	}
	bucketLen := 13 // hour prefix of RFC3339
	bucketName := "hour"
	if days > 7 {
		bucketLen = 10 // day prefix
		bucketName = "day"
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)

	rows, err := s.queries.ListProbeQualityBuckets(ctx, db.ListProbeQualityBucketsParams{
		BucketLen: int64(bucketLen),
		Cutoff:    cutoff,
	})
	if err != nil {
		return QualityHistoryReport{}, fmt.Errorf("quality history: buckets: %w", err)
	}
	targets, err := s.queries.ListProbeTargets(ctx)
	if err != nil {
		return QualityHistoryReport{}, fmt.Errorf("quality history: list targets: %w", err)
	}
	nets, err := s.queries.ListNetworks(ctx)
	if err != nil {
		return QualityHistoryReport{}, fmt.Errorf("quality history: list networks: %w", err)
	}
	networkByAgent := make(map[string]string, len(nets))
	for _, n := range nets {
		if n.AgentID != nil && strings.TrimSpace(*n.AgentID) != "" {
			networkByAgent[strings.TrimSpace(*n.AgentID)] = n.Name
		}
	}
	targetByName := make(map[string]db.ProbeTarget, len(targets))
	for _, t := range targets {
		targetByName[t.Name] = t
	}
	idOf := func(name string) (int64, bool) {
		t, ok := targetByName[name]
		if !ok {
			return 0, false
		}
		return t.ID, true
	}

	// buckets[bucket][qualityKey] → synthesized track agg. The single-element
	// latency slice makes stats().P50Ms equal the SQL mean, which is exactly
	// the documented per-bucket approximation; the chain then runs untouched.
	type pointAcc struct {
		okSum, okCount float64
	}
	buckets := make(map[string]map[qualityKey]*trackAgg)
	acc := make(map[string]map[string]*pointAcc) // bucket → vantage → weighted latency
	for _, r := range rows {
		perBucket := buckets[r.Bucket]
		if perBucket == nil {
			perBucket = make(map[qualityKey]*trackAgg)
			buckets[r.Bucket] = perBucket
			acc[r.Bucket] = make(map[string]*pointAcc)
		}
		k := qualityKey{r.TargetID, r.Vantage}
		a := perBucket[k]
		if a == nil {
			a = &trackAgg{}
			perBucket[k] = a
		}
		a.samples += int(r.Samples)
		if r.OkCount != nil {
			a.ok += int(*r.OkCount)
		}
		if r.AvgMs != nil && *r.AvgMs > 0 {
			a.latencies = []float64{*r.AvgMs}
			// Weight the point-level mean by successful samples so a busy
			// leg counts proportionally.
			va := acc[r.Bucket][r.Vantage]
			if va == nil {
				va = &pointAcc{}
				acc[r.Bucket][r.Vantage] = va
			}
			va.okSum += *r.AvgMs * float64(*r.OkCount)
			va.okCount += float64(*r.OkCount)
		}
	}
	bucketKeys := make([]string, 0, len(buckets))
	for b := range buckets {
		bucketKeys = append(bucketKeys, b)
	}
	sort.Strings(bucketKeys)

	// bucketStart turns a prefix slice back into a bucket-start timestamp.
	bucketStart := func(b string) string {
		switch bucketLen {
		case 13: // "2026-10-24T05"
			return b + ":00:00Z"
		default: // "2026-10-24"
			return b + "T00:00:00Z"
		}
	}

	report := QualityHistoryReport{Days: days, Bucket: bucketName}
	groupNames := make([]string, 0, len(s.cfg.Groups))
	for name := range s.cfg.Groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	for _, group := range groupNames {
		cfgTargets := s.cfg.Groups[group]
		gh := QualityHistoryGroup{Name: group, Role: "reference"}
		if group == QualityPrimaryGroup {
			gh.Role = "primary"
		}
		seriesByVantage := make(map[string]*QualityHistorySeries)
		for _, b := range bucketKeys {
			agg := buckets[b]
			// Every vantage with ANY leg in this bucket gets a point - a
			// bucket of pure failures (avg latency never set) must still
			// surface as the egress_down/insufficient bucket it is.
			vs := make(map[string]bool)
			for k := range agg {
				vs[k.vantage] = true
			}
			for vantage := range vs {
				vr := judgeVantage(cfgTargets, agg, idOf, vantage, s.cfg)
				ser := seriesByVantage[vantage]
				if ser == nil {
					ser = &QualityHistorySeries{Vantage: vantage}
					seriesByVantage[vantage] = ser
				}
				// The trend line carries the raw mean ok-rate over the
				// bucket's evaluated legs (score carries the chain caps and
				// the degraded penalty; ok-rate should not).
				p := QualityHistoryPoint{
					T:       bucketStart(b),
					OkRate:  bucketOkRate(cfgTargets, agg, idOf, vantage),
					Samples: bucketSamples(cfgTargets, agg, idOf, vantage),
					Score:   vr.Score,
					Verdict: vr.Verdict,
				}
				if va := acc[b][vantage]; va != nil && va.okCount > 0 {
					p.AvgMs = va.okSum / va.okCount
				}
				ser.Points = append(ser.Points, p)
			}
		}
		for _, v := range sortedVantages(seriesByVantage) {
			ser := seriesByVantage[v]
			if name := networkNameFor(v, networkByAgent); name != "" {
				ser.NetworkName = name
			}
			gh.Series = append(gh.Series, *ser)
		}
		report.Groups = append(report.Groups, gh)
	}
	return report, nil
}

// bucketOkRate is the mean ok-rate of the group's legs with data in this
// bucket (the same population judgeVantage evaluated - target-down isolated
// legs excluded there are excluded here by recomputing membership).
func bucketOkRate(
	cfgTargets []config.ProbeQualityTarget,
	agg map[qualityKey]*trackAgg,
	idOf func(name string) (int64, bool),
	vantage string,
) float64 {
	sum, n := 0.0, 0
	for _, qt := range cfgTargets {
		st, ok := legStatsInBucket(qt, agg, idOf, vantage)
		if !ok {
			continue
		}
		sum += st.OkRate
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// bucketSamples totals the samples of the same evaluated legs.
func bucketSamples(
	cfgTargets []config.ProbeQualityTarget,
	agg map[qualityKey]*trackAgg,
	idOf func(name string) (int64, bool),
	vantage string,
) int {
	total := 0
	for _, qt := range cfgTargets {
		st, ok := legStatsInBucket(qt, agg, idOf, vantage)
		if !ok {
			continue
		}
		total += st.Samples
	}
	return total
}

// legStatsInBucket resolves one leg's stats, applying the same cross-vantage
// target-down isolation judgeVantage uses (a target failing EVERYWHERE in
// this bucket is target-side and excluded).
func legStatsInBucket(
	qt config.ProbeQualityTarget,
	agg map[qualityKey]*trackAgg,
	idOf func(name string) (int64, bool),
	vantage string,
) (QualityTrackStats, bool) {
	id, ok := idOf(qt.Name)
	if !ok {
		return QualityTrackStats{}, false
	}
	a := agg[qualityKey{id, vantage}]
	if a == nil || a.samples == 0 {
		return QualityTrackStats{}, false
	}
	perV := make(map[string]QualityTrackStats)
	for k, other := range agg {
		if k.targetID == id {
			perV[k.vantage] = other.stats()
		}
	}
	if len(perV) > 1 && crossVantageVerdict(perV) == "target_down" {
		return QualityTrackStats{}, false
	}
	return a.stats(), true
}

func sortedVantages(m map[string]*QualityHistorySeries) []string {
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
