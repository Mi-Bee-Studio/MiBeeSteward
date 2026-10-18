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
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// Quality verdicts (#608). The per-vantage reason strings are STABLE CODES:
// the UI maps them to localized text, unknown codes fall back to raw.
const (
	QualityVerdictOK               = "ok"
	QualityVerdictDegraded         = "degraded"
	QualityVerdictEgressDown       = "egress_down"
	QualityVerdictDNSFault         = "dns_fault"
	QualityVerdictUpstreamResolver = "upstream_resolver"
	QualityVerdictInsufficient     = "insufficient"

	// QualityPrimaryGroup names the group whose verdict IS the network's
	// verdict. Every other group is reference-only: displayed separately,
	// never folded into the primary judgement (cross-border variance is its
	// own signal, not an egress fault).
	QualityPrimaryGroup = "domestic"
)

// qualityKey identifies one (target, vantage) track within a window.
type qualityKey struct {
	targetID int64
	vantage  string
}

// qualityLeg is one classified matrix leg feeding the verdict chain.
type qualityLeg struct {
	name   string
	module string
	st     QualityTrackStats
}

// Target categories (#613): the management UI groups targets and the quality
// analyzer computes per these. Derivation is deterministic - no stored tag:
//   - quality  : source=system (the built-in egress matrix, config-managed)
//   - lan      : device-bound (source=auto, or manual with a device_id)
//   - external : manual targets without a device binding (business sites)
const (
	ProbeCategoryLAN      = "lan"
	ProbeCategoryExternal = "external"
	ProbeCategoryQuality  = "quality"
)

// TargetCategory derives one target's management category.
func TargetCategory(t db.ProbeTarget) string {
	switch {
	case t.Source == domain.ProbeSourceSystem:
		return ProbeCategoryQuality
	case t.DeviceID != nil || t.Source == domain.ProbeSourceAuto:
		return ProbeCategoryLAN
	default:
		return ProbeCategoryExternal
	}
}

// QualityService seeds the built-in egress-quality matrix from config and
// computes per-vantage verdicts over a sliding window. Read-time analysis:
// no state table, no notifications (the rejected "B" direction), pure
// aggregation over probe_results per call.
type QualityService struct {
	queries *db.Queries
	cfg     config.ProbeQualityConfig
	logger  *slog.Logger
}

func NewQualityService(queries *db.Queries, cfg config.ProbeQualityConfig, logger *slog.Logger) *QualityService {
	if logger == nil {
		logger = slog.Default()
	}
	return &QualityService{queries: queries, cfg: cfg, logger: logger}
}

// Config returns the effective quality config (the handler defaults the
// window query param from it).
func (s *QualityService) Config() config.ProbeQualityConfig { return s.cfg }

// Seed reconciles the system-target matrix with the config (#608):
//   - enabled: create missing rows, refresh drifted ones (module/target/
//     options), delete source=system rows that left the config (result
//     history cascades - removing a config entry removes the probe).
//   - disabled: every system target is parked (disabled, kept for history).
//
// Called once at startup; idempotent.
func (s *QualityService) Seed(ctx context.Context) error {
	existing, err := s.queries.ListProbeTargets(ctx)
	if err != nil {
		return fmt.Errorf("quality seed: list targets: %w", err)
	}
	byName := make(map[string]db.ProbeTarget, len(existing))
	var systemRows []db.ProbeTarget
	for _, t := range existing {
		byName[t.Name] = t
		if t.Source == domain.ProbeSourceSystem {
			systemRows = append(systemRows, t)
		}
	}

	if !s.cfg.Enabled {
		parked := 0
		for _, t := range systemRows {
			if t.Enabled == 1 {
				if err := s.queries.ToggleProbeTargetEnabled(ctx, db.ToggleProbeTargetEnabledParams{Enabled: 0, ID: t.ID}); err != nil {
					return fmt.Errorf("quality seed: disable %s: %w", t.Name, err)
				}
				parked++
			}
		}
		if parked > 0 {
			s.logger.Info("probe quality: disabled (config off), system targets parked", "targets", parked)
		}
		return nil
	}

	wanted := make(map[string]bool)
	for _, targets := range s.cfg.Groups {
		for _, qt := range targets {
			wanted[qt.Name] = true
			optsJSON, err := qualityOptionsJSON(qt.Options)
			if err != nil {
				return fmt.Errorf("quality seed: %s: %w", qt.Name, err)
			}
			if prev, ok := byName[qt.Name]; ok {
				if prev.Source != domain.ProbeSourceSystem {
					s.logger.Warn("probe quality: name already taken by a non-system target, skipping", "name", qt.Name)
					continue
				}
				if prev.Module != qt.Module || prev.Target != qt.Target || prev.Options != optsJSON {
					if _, err := s.queries.UpdateProbeTarget(ctx, db.UpdateProbeTargetParams{
						Name: prev.Name, Module: qt.Module, Target: qt.Target,
						IntervalSeconds: prev.IntervalSeconds, TimeoutSeconds: prev.TimeoutSeconds,
						Enabled: prev.Enabled, Notes: prev.Notes, Vantage: domain.ProbeVantageAll,
						Options: optsJSON, DeviceID: nil, ID: prev.ID,
					}); err != nil {
						return fmt.Errorf("quality seed: refresh %s: %w", qt.Name, err)
					}
					s.logger.Info("probe quality: target refreshed from config", "name", qt.Name)
				}
				continue
			}
			created, err := s.queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
				Name: qt.Name, Module: qt.Module, Target: qt.Target,
				IntervalSeconds: int64(s.cfg.IntervalSeconds), TimeoutSeconds: 10,
				Enabled: 1, Notes: "egress-quality matrix member (#608), managed by probe.quality config",
				Vantage: domain.ProbeVantageAll, Options: optsJSON,
				Source: domain.ProbeSourceSystem,
			})
			if err != nil {
				return fmt.Errorf("quality seed: create %s: %w", qt.Name, err)
			}
			s.logger.Info("probe quality: target seeded", "name", qt.Name, "id", created.ID)
		}
	}

	// Rows that left the config are deleted (explicit cascade, same as the
	// CRUD delete path).
	for _, t := range systemRows {
		if wanted[t.Name] {
			continue
		}
		if _, err := s.queries.DeleteProbeResultsByTarget(ctx, t.ID); err != nil {
			return fmt.Errorf("quality seed: purge results %s: %w", t.Name, err)
		}
		if _, err := s.queries.DeleteProbeTLSCertsByTarget(ctx, t.ID); err != nil {
			return fmt.Errorf("quality seed: purge certs %s: %w", t.Name, err)
		}
		if _, err := s.queries.DeleteProbeTarget(ctx, t.ID); err != nil {
			return fmt.Errorf("quality seed: delete %s: %w", t.Name, err)
		}
		s.logger.Info("probe quality: target removed (left the config)", "name", t.Name)
	}
	return nil
}

// qualityOptionsJSON renders the config's loose options map into the stored
// JSON shape (empty map → "", the option-less convention).
func qualityOptionsJSON(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// QualityTrackStats is one (target, vantage) window aggregate.
type QualityTrackStats struct {
	OkRate     float64 `json:"ok_rate"`
	P50Ms      float64 `json:"p50_ms"`
	Samples    int     `json:"samples"`
	LastStatus string  `json:"last_status,omitempty"`
}

// QualityTargetMatrix is one matrix column: the per-vantage stats of one
// target plus the cross-vantage isolation verdict.
type QualityTargetMatrix struct {
	Name         string                       `json:"name"`
	Module       string                       `json:"module"`
	Target       string                       `json:"target"`
	CrossVantage string                       `json:"cross_vantage"` // ok | target_down | mixed | no_data
	PerVantage   map[string]QualityTrackStats `json:"per_vantage"`
}

// QualityVantageReport is one vantage's verdict within one group.
type QualityVantageReport struct {
	Vantage     string   `json:"vantage"` // center | agent:{id}
	NetworkName string   `json:"network_name,omitempty"`
	Verdict     string   `json:"verdict"`
	Score       int      `json:"score"`
	Reasons     []string `json:"reasons"`
}

// QualityGroupReport is one config group's slice of the quality matrix
// (quality category only).
type QualityGroupReport struct {
	Name     string                 `json:"name"`
	Role     string                 `json:"role"` // primary | reference
	Vantages []QualityVantageReport `json:"vantages"`
	Targets  []QualityTargetMatrix  `json:"targets"`
}

// QualityCategoryReport is one category's slice of the report. lan/external
// carry simple ok/degraded verdicts over their own targets; quality carries
// the full egress verdict chain, with the config groups nested.
type QualityCategoryReport struct {
	Category string                 `json:"category"` // lan | external | quality
	Vantages []QualityVantageReport `json:"vantages"`
	Targets  []QualityTargetMatrix  `json:"targets"`
	Groups   []QualityGroupReport   `json:"groups,omitempty"` // quality only
}

// QualityReport is the GET /api/v1/probe-quality payload (#613: computed per
// management category).
type QualityReport struct {
	WindowMinutes int                     `json:"window_minutes"`
	Categories    []QualityCategoryReport `json:"categories"`
}

// Analyze aggregates the window's probe_results into per-CATEGORY verdicts
// (#613): lan (device-bound targets), external (manual business targets) and
// quality (the built-in matrix, verdict chain inside). Read-only and
// deterministic; the window holds a few thousand rows at most, percentiles
// are exact (computed in Go, no SQL approximation).
func (s *QualityService) Analyze(ctx context.Context, windowMinutes int) (QualityReport, error) {
	if windowMinutes <= 0 {
		windowMinutes = s.cfg.WindowMinutes
	}
	cutoff := time.Now().UTC().Add(-time.Duration(windowMinutes) * time.Minute).Format(time.RFC3339)
	rows, err := s.queries.ListProbeResultsSince(ctx, cutoff)
	if err != nil {
		return QualityReport{}, fmt.Errorf("quality analyze: results since: %w", err)
	}
	targets, err := s.queries.ListProbeTargets(ctx)
	if err != nil {
		return QualityReport{}, fmt.Errorf("quality analyze: list targets: %w", err)
	}
	nets, err := s.queries.ListNetworks(ctx)
	if err != nil {
		return QualityReport{}, fmt.Errorf("quality analyze: list networks: %w", err)
	}
	networkByAgent := make(map[string]string, len(nets))
	for _, n := range nets {
		if n.AgentID != nil && strings.TrimSpace(*n.AgentID) != "" {
			networkByAgent[strings.TrimSpace(*n.AgentID)] = n.Name
		}
	}

	// Aggregate once: (target, vantage) → window stats.
	agg := make(map[qualityKey]*trackAgg)
	for _, r := range rows {
		k := qualityKey{r.TargetID, r.Vantage}
		a := agg[k]
		if a == nil {
			a = &trackAgg{latencies: make([]float64, 0, 8)}
			agg[k] = a
		}
		a.samples++
		a.last = r.Status
		if r.Status == "success" {
			a.ok++
			a.latencies = append(a.latencies, r.LatencyMs)
		}
	}

	statsOf := func(id int64, vantage string) (QualityTrackStats, bool) {
		a := agg[qualityKey{id, vantage}]
		if a == nil {
			return QualityTrackStats{}, false
		}
		return a.stats(), true
	}

	// Bucket the enabled targets by management category.
	buckets := map[string][]db.ProbeTarget{
		ProbeCategoryLAN: {}, ProbeCategoryExternal: {}, ProbeCategoryQuality: {},
	}
	for _, t := range targets {
		if t.Enabled == 1 {
			buckets[TargetCategory(t)] = append(buckets[TargetCategory(t)], t)
		}
	}

	networkName := func(v string) string { return networkNameFor(v, networkByAgent) }
	report := QualityReport{WindowMinutes: windowMinutes}

	// lan + external: simple per-vantage health over the category's own
	// targets (each target only ever has its own vantage's track - a LAN
	// service is probed from its own network - so no cross-vantage
	// isolation applies here).
	for _, cat := range []string{ProbeCategoryLAN, ProbeCategoryExternal} {
		cr := QualityCategoryReport{Category: cat}
		vantageSet := make(map[string]bool)
		for _, t := range buckets[cat] {
			per := make(map[string]QualityTrackStats)
			for k := range agg {
				if k.targetID == t.ID {
					per[k.vantage] = agg[k].stats()
					vantageSet[k.vantage] = true
				}
			}
			cr.Targets = append(cr.Targets, QualityTargetMatrix{
				Name: t.Name, Module: t.Module, Target: t.Target,
				CrossVantage: crossVantageVerdict(per), PerVantage: per,
			})
		}
		for _, v := range sortedKeys(vantageSet) {
			vr := judgeSimpleCategory(buckets[cat], v, statsOf, s.cfg)
			if name := networkName(v); name != "" {
				vr.NetworkName = name
			}
			cr.Vantages = append(cr.Vantages, vr)
		}
		report.Categories = append(report.Categories, cr)
	}

	// quality: the deterministic egress verdict chain over the config
	// matrix (system targets), groups nested.
	cr := QualityCategoryReport{Category: ProbeCategoryQuality}
	targetByName := make(map[string]db.ProbeTarget, len(targets))
	for _, t := range targets {
		targetByName[t.Name] = t
	}
	groupNames := make([]string, 0, len(s.cfg.Groups))
	for name := range s.cfg.Groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	for _, group := range groupNames {
		gr := s.analyzeGroup(group, s.cfg.Groups[group], targetByName, agg, networkName)
		cr.Groups = append(cr.Groups, gr)
		if group != QualityPrimaryGroup {
			continue
		}
		// The category-level view mirrors the PRIMARY group's verdicts; the
		// reference groups stay nested below it in the UI.
		cr.Vantages = gr.Vantages
	}
	cr.Targets = qualityMatrixTargets(s.cfg, targetByName, agg)
	report.Categories = append(report.Categories, cr)
	return report, nil
}

// analyzeGroup computes one quality config group (verdict chain + matrix
// columns).
func (s *QualityService) analyzeGroup(
	group string,
	cfgTargets []config.ProbeQualityTarget,
	targetByName map[string]db.ProbeTarget,
	agg map[qualityKey]*trackAgg,
	networkName func(vantage string) string,
) QualityGroupReport {
	gr := QualityGroupReport{Name: group, Role: "reference"}
	if group == QualityPrimaryGroup {
		gr.Role = "primary"
	}
	idOf := func(name string) (int64, bool) {
		t, ok := targetByName[name]
		if !ok {
			return 0, false
		}
		return t.ID, true
	}
	perVantageOf := func(name string) map[string]QualityTrackStats {
		out := make(map[string]QualityTrackStats)
		if id, ok := idOf(name); ok {
			for k, a := range agg {
				if k.targetID == id {
					out[k.vantage] = a.stats()
				}
			}
		}
		return out
	}

	for _, qt := range cfgTargets {
		per := perVantageOf(qt.Name)
		gr.Targets = append(gr.Targets, QualityTargetMatrix{
			Name: qt.Name, Module: qt.Module, Target: qt.Target,
			CrossVantage: crossVantageVerdict(per), PerVantage: per,
		})
	}
	vantageSet := make(map[string]bool)
	for _, qt := range cfgTargets {
		for v := range perVantageOf(qt.Name) {
			vantageSet[v] = true
		}
	}
	for _, v := range sortedKeys(vantageSet) {
		vr := judgeVantage(cfgTargets, agg, idOf, v, s.cfg)
		if name := networkName(v); name != "" {
			vr.NetworkName = name
		}
		gr.Vantages = append(gr.Vantages, vr)
	}
	return gr
}

// qualityMatrixTargets flattens the config groups into the category-level
// column list (display only - the verdicts live in the groups).
func qualityMatrixTargets(cfg config.ProbeQualityConfig, targetByName map[string]db.ProbeTarget, agg map[qualityKey]*trackAgg) []QualityTargetMatrix {
	var out []QualityTargetMatrix
	for _, group := range cfg.Groups {
		for _, qt := range group {
			per := make(map[string]QualityTrackStats)
			if t, ok := targetByName[qt.Name]; ok {
				for k, a := range agg {
					if k.targetID == t.ID {
						per[k.vantage] = a.stats()
					}
				}
			}
			out = append(out, QualityTargetMatrix{
				Name: qt.Name, Module: qt.Module, Target: qt.Target,
				CrossVantage: crossVantageVerdict(per), PerVantage: per,
			})
		}
	}
	return out
}

// judgeSimpleCategory is the lan/external verdict: no egress semantics, just
// window health - mean ok-rate over the category's evaluated legs against
// the ok-rate threshold, per-module p50 budgets, insufficient below two
// samples.
func judgeSimpleCategory(
	bucket []db.ProbeTarget,
	vantage string,
	statsOf func(id int64, vantage string) (QualityTrackStats, bool),
	cfg config.ProbeQualityConfig,
) QualityVantageReport {
	vr := QualityVantageReport{
		Vantage: vantage,
		Verdict: QualityVerdictInsufficient,
		Reasons: []string{"insufficient_data"},
	}
	var legs []qualityLeg
	totalSamples := 0
	for _, t := range bucket {
		st, ok := statsOf(t.ID, vantage)
		if !ok || st.Samples == 0 {
			continue
		}
		totalSamples += st.Samples
		legs = append(legs, qualityLeg{name: t.Name, module: t.Module, st: st})
	}
	if len(legs) == 0 || totalSamples < 2 {
		return vr
	}
	vr.Reasons = vr.Reasons[:0]

	okSum := 0.0
	for _, l := range legs {
		okSum += l.st.OkRate
	}
	if okSum/float64(len(legs)) < cfg.OkRateThreshold {
		vr.Reasons = append(vr.Reasons, "ok_rate_low")
	}
	for _, l := range legs {
		budget := float64(cfg.HTTPDegradedMs)
		if l.module == "dns" {
			budget = float64(cfg.DNSDegradedMs)
		}
		if l.st.P50Ms > 0 && l.st.P50Ms > budget {
			vr.Reasons = append(vr.Reasons, "latency_high")
			break
		}
	}
	vr.Score = okRateScore(legs)
	if len(vr.Reasons) > 0 {
		vr.Verdict = QualityVerdictDegraded
		vr.Score = maxInt(vr.Score-20, 0)
	} else {
		vr.Verdict = QualityVerdictOK
	}
	return vr
}

// trackAgg accumulates one (target, vantage) window; latencies count only
// successes (a failure's latency is the timeout burn, not network RTT).
type trackAgg struct {
	samples   int
	ok        int
	last      string
	latencies []float64
}

func (a *trackAgg) stats() QualityTrackStats {
	st := QualityTrackStats{Samples: a.samples, LastStatus: a.last}
	if a.samples > 0 {
		st.OkRate = float64(a.ok) / float64(a.samples)
	}
	sorted := append([]float64(nil), a.latencies...)
	sort.Float64s(sorted)
	if n := len(sorted); n > 0 {
		st.P50Ms = sorted[(n-1)/2]
	}
	return st
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// crossVantageVerdict isolates target-side failures: failing EVERYWHERE is
// the target's problem (excluded from the network verdicts), failing
// SOMEWHERE is that network's story.
func crossVantageVerdict(perVantage map[string]QualityTrackStats) string {
	if len(perVantage) == 0 {
		return "no_data"
	}
	allDown, anyDown := true, false
	for _, st := range perVantage {
		if st.OkRate > 0.5 {
			allDown = false
		} else {
			anyDown = true
		}
	}
	switch {
	case allDown:
		return "target_down"
	case anyDown:
		return "mixed"
	default:
		return "ok"
	}
}

// judgeVantage applies the deterministic verdict chain to one vantage:
//
//	egress_down > dns_fault > upstream_resolver > degraded > ok
//
// Legs are classified per target: "direct" = tcp with an IP-literal target
// (no DNS anywhere in the path), "dns" = the dns module, "http" = the http
// module (plus non-literal tcp, which still exercises resolution).
func judgeVantage(
	cfgTargets []config.ProbeQualityTarget,
	agg map[qualityKey]*trackAgg,
	idOf func(name string) (int64, bool),
	vantage string,
	cfg config.ProbeQualityConfig,
) QualityVantageReport {
	vr := QualityVantageReport{
		Vantage: vantage,
		Verdict: QualityVerdictInsufficient,
		Reasons: []string{"insufficient_data"},
	}
	stat := func(name string) (QualityTrackStats, bool) {
		id, ok := idOf(name)
		if !ok {
			return QualityTrackStats{}, false
		}
		a := agg[qualityKey{id, vantage}]
		if a == nil {
			return QualityTrackStats{}, false
		}
		return a.stats(), true
	}

	var directs, dnses, others []qualityLeg
	for _, qt := range cfgTargets {
		st, ok := stat(qt.Name)
		if !ok || st.Samples == 0 {
			continue
		}
		// Cross-vantage isolation: columns failing EVERYWHERE are the
		// target's fault, not this network's. Only meaningful with more
		// than one reporting vantage - a single-vantage matrix failing
		// wholesale must read as the network's outage, not be explained
		// away as target-side.
		perV := make(map[string]QualityTrackStats)
		if id, ok := idOf(qt.Name); ok {
			for k, a := range agg {
				if k.targetID == id {
					perV[k.vantage] = a.stats()
				}
			}
		}
		if len(perV) > 1 && crossVantageVerdict(perV) == "target_down" {
			continue
		}
		leg := qualityLeg{name: qt.Name, module: qt.Module, st: st}
		switch {
		case qt.Module == "dns":
			dnses = append(dnses, leg)
		case qt.Module == "tcp" && ipLiteralHost(qt.Target):
			directs = append(directs, leg)
		default:
			others = append(others, leg) // http legs and host-named tcp legs
		}
	}
	all := append(append(directs, dnses...), others...)
	if len(all) == 0 {
		return vr
	}
	vr.Reasons = vr.Reasons[:0]

	failed := func(l qualityLeg) bool { return l.st.OkRate < 0.5 }
	passed := func(l qualityLeg) bool { return l.st.OkRate >= cfg.OkRateThreshold }
	allFailed := func(legs []qualityLeg) bool {
		if len(legs) == 0 {
			return false
		}
		for _, l := range legs {
			if !failed(l) {
				return false
			}
		}
		return true
	}

	// 1. egress_down: the DNS-free path itself is dead - direct legs failing
	//    plus every http leg failing; nothing reaches the outside.
	if allFailed(directs) && allFailed(others) {
		vr.Verdict = QualityVerdictEgressDown
		vr.Reasons = append(vr.Reasons, "egress_down.all_paths_failing")
		vr.Score = minInt(okRateScore(all), 25)
		return vr
	}
	// 2. dns_fault: the direct IP path WORKS but every resolution-dependent
	//    leg (http + dns) fails - this network's resolver path is broken.
	directOK := len(directs) > 0
	for _, l := range directs {
		if failed(l) {
			directOK = false
		}
	}
	if directOK && allFailed(others) && allFailed(dnses) && (len(others) > 0 || len(dnses) > 0) {
		vr.Verdict = QualityVerdictDNSFault
		vr.Reasons = append(vr.Reasons, "dns_fault.direct_ok_name_resolution_dead")
		vr.Score = minInt(okRateScore(all), 25)
		return vr
	}
	// 3. upstream_resolver: the resolvers SPLIT (one answers, one does not)
	//    - the failing resolver's problem, not this network's egress.
	if len(dnses) > 1 {
		var okResolver, failResolver bool
		for _, l := range dnses {
			if passed(l) {
				okResolver = true
			}
			if failed(l) {
				failResolver = true
			}
		}
		if okResolver && failResolver {
			vr.Verdict = QualityVerdictUpstreamResolver
			for _, l := range dnses {
				if failed(l) {
					vr.Reasons = append(vr.Reasons, "upstream_resolver.failing:"+l.name)
				}
			}
			vr.Score = okRateScore(all)
			return vr
		}
	}
	// 4. degraded / ok: overall ok-rate and per-module p50 budgets.
	var reasons []string
	okSum := 0.0
	for _, l := range all {
		okSum += l.st.OkRate
	}
	if okSum/float64(len(all)) < cfg.OkRateThreshold {
		reasons = append(reasons, "ok_rate_low")
	}
	for _, l := range all {
		budget := float64(cfg.HTTPDegradedMs)
		if l.module == "dns" {
			budget = float64(cfg.DNSDegradedMs)
		}
		if l.st.P50Ms > 0 && l.st.P50Ms > budget {
			reasons = append(reasons, "latency_high")
			break
		}
	}
	vr.Score = okRateScore(all)
	if len(reasons) > 0 {
		vr.Verdict = QualityVerdictDegraded
		vr.Reasons = reasons
		vr.Score = maxInt(vr.Score-20, 0)
	} else {
		vr.Verdict = QualityVerdictOK
		vr.Reasons = []string{}
	}
	return vr
}

// ipLiteralHost reports whether a host:port target's host part is an IP
// literal (the DNS-free direct leg detector).
func ipLiteralHost(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	return net.ParseIP(host) != nil
}

func networkNameFor(vantage string, byAgent map[string]string) string {
	if id, ok := strings.CutPrefix(vantage, domain.ProbeVantageAgentPrefix); ok {
		return byAgent[id]
	}
	return ""
}

// okRateScore: the mean ok-rate of the evaluated legs, 0-100.
func okRateScore(legs []qualityLeg) int {
	if len(legs) == 0 {
		return 0
	}
	sum := 0.0
	for _, l := range legs {
		sum += l.st.OkRate
	}
	return int(sum/float64(len(legs))*100 + 0.5)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
