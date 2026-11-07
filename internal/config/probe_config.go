// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package config

import "fmt"

// ProbeConfig is the probe (拨测) engine block: concurrency, the built-in
// egress-quality matrix (#608), and the discover-then-probe autogen policy
// (#606). Everything except retention (retention.probe_results_days) lives
// here; per-target interval/timeout stay DB columns on probe_targets.
type ProbeConfig struct {
	// MaxConcurrency bounds simultaneous probes (semaphore). 0 = default 8,
	// the historical hard-coded value.
	MaxConcurrency int `koanf:"max_concurrency"`
	// NotifyFailThreshold is how many consecutive failing runs a probe track
	// needs before probe_failed fires (0 = default 3; the #608 liveness
	// wiring). Lower = noisier but faster detection; at the recommended 300s
	// cadence the default declares within 15 minutes.
	NotifyFailThreshold int `koanf:"notify_fail_threshold"`
	// Quality configures the built-in network egress quality assessment
	// (#608): a system-seeded matrix of public probe points, executed from
	// every vantage (center + all agents), analyzed per network.
	Quality ProbeQualityConfig `koanf:"quality"`
	// Autogen is the discover-then-probe policy (#606): auto-create probe
	// targets for discovered services. Default OFF - it writes rows on its
	// own, so it must be a deliberate choice.
	Autogen ProbeAutogenConfig `koanf:"autogen"`
	// Egress drives the egress-identity recorder (#718): every interval the
	// center (and later agents) asks a set of echo sources which public IP
	// the current egress presents, enriches the distinct IPs with their ASN,
	// and stores the round in the probe_ext.db side database. Recording only
	// - change notifications are deliberately out of scope (the #716 ruling:
	// changes never alert on their own).
	Egress ProbeEgressConfig `koanf:"egress"`
	// Trace drives the zero-privilege path recorder (#719): every interval
	// each enabled external/quality target gets one TCP/ICMP TTL walk; the
	// latest path per target is what the probes page shows (#716 UI).
	Trace ProbeTraceConfig `koanf:"trace"`
}

// ProbeEgressConfig tunes the egress-identity rounds (#718).
type ProbeEgressConfig struct {
	Enabled bool `koanf:"enabled"`
	// IntervalSeconds between rounds (center-side; agents get it via the
	// egress plan when the agent side lands).
	IntervalSeconds int `koanf:"interval_seconds"`
	// ASNResolvers are the DNS servers used for the Team Cymru origin ASN
	// TXT lookups, in preference order. The default public resolver works
	// from both survey networks; the system resolver often blocks the TXT
	// CHAOS-ish queries.
	ASNResolvers []string `koanf:"asn_resolvers"`
	// Sources replaces the built-in echo-source set entirely when non-empty.
	// Each entry: kind http (Target = URL returning the IP in the body),
	// stun (Target = host:port), or dns (Target = "server|qname|TXT").
	Sources []ProbeEgressSource `koanf:"sources"`
}

// ProbeEgressSource is one public-IP echo source.
type ProbeEgressSource struct {
	Name   string `koanf:"name" json:"name"`
	Kind   string `koanf:"kind" json:"kind"` // http | stun | dns
	Target string `koanf:"target" json:"target"`
}

// ProbeTraceConfig tunes the path recorder (#719, center side first).
type ProbeTraceConfig struct {
	// Categories lists the probe-target categories that get periodic traces
	// (lan | external | quality). Default external+quality; lan stays off
	// (internal paths change with every ARP flap and are the topology page's
	// job, not the egress path question).
	Categories []string `koanf:"categories"`
	// IntervalMinutes between baseline traces per target.
	IntervalMinutes int `koanf:"interval_minutes"`
	// MaxTTL bounds the TTL walk.
	MaxTTL int `koanf:"max_ttl"`
	// PerHopMs is each TTL attempt's wait. Silent-middle egress (the survey's
	// 63.x case: hops 2..N-1 all mute, destination at 12-17) means NO early
	// give-up - the walk always runs to reached/max-ttl.
	PerHopMs int `koanf:"per_hop_ms"`
	// Concurrency bounds simultaneous traces.
	Concurrency int `koanf:"concurrency"`
}

// ProbeQualityConfig drives the egress-quality matrix. The default target
// set ships China-mainstream points plus an international reference group
// (deliberately excluded from the primary verdict: cross-border variance is
// its own signal, not an egress fault). Every value is configurable; the
// defaults are only a starting point.
type ProbeQualityConfig struct {
	Enabled bool `koanf:"enabled"`
	// WindowMinutes is the lookback window the analyzer aggregates over.
	WindowMinutes int `koanf:"window_minutes"`
	// IntervalSeconds is the seeded cadence of every quality target.
	IntervalSeconds int `koanf:"interval_seconds"`
	// HTTPDegradedMs / DNSDegradedMs are the p50 latency thresholds that mark
	// a vantage degraded (on top of the ok-rate threshold).
	HTTPDegradedMs int `koanf:"http_degraded_ms"`
	DNSDegradedMs  int `koanf:"dns_degraded_ms"`
	// OkRateThreshold (0..1) is the minimum success rate within the window.
	OkRateThreshold float64 `koanf:"ok_rate_threshold"`
	// Groups maps a group name to its probe points. The reserved names
	// "domestic" (primary verdict) and "international" (reference, excluded
	// from the primary verdict) drive the analyzer's grouping; other names
	// are treated as reference groups. Empty map = use DefaultQualityGroups.
	Groups map[string][]ProbeQualityTarget `koanf:"groups"`
}

// ProbeQualityTarget is one matrix member: a name (the probe_targets row
// name, stable across reseeds), a module, a target string, and optional
// per-module options (same shape as domain.ProbeOptions).
type ProbeQualityTarget struct {
	Name    string         `koanf:"name" json:"name"`
	Module  string         `koanf:"module" json:"module"`
	Target  string         `koanf:"target" json:"target"`
	Options map[string]any `koanf:"options" json:"options,omitempty"`
}

// ProbeAutogenConfig is the policy for auto-generating device-bound probe
// targets from discovered services (#606). Manual targets are never touched.
type ProbeAutogenConfig struct {
	Enabled bool `koanf:"enabled"`
	// Services lists the service identities eligible for auto targets
	// (http, https, ... matching host_services.service). Empty = http+https.
	Services []string `koanf:"services"`
	// DeviceTypes restricts generation to those device types; empty = all.
	DeviceTypes []string `koanf:"device_types"`
	// IntervalSeconds is the auto targets' probe interval.
	IntervalSeconds int `koanf:"interval_seconds"`
	// MaxTargets caps the auto population (a 1000-device LAN must not
	// explode into 3000 targets).
	MaxTargets int `koanf:"max_targets"`
	// SweepIntervalMinutes is the reconcile cadence.
	SweepIntervalMinutes int `koanf:"sweep_interval_minutes"`
}

// DefaultEgressSources is the shipped echo-source set (#718): a domestic and
// an international mix across three transports, because no single source is
// reliable from every network (survey 2026-11-07: per-source availability
// ranged from always-dead to ~100%). Public anycast/service addresses only.
func DefaultEgressSources() []ProbeEgressSource {
	return []ProbeEgressSource{
		{Name: "http-icanhazip", Kind: "http", Target: "https://ipv4.icanhazip.com"},
		{Name: "http-aws-checkip", Kind: "http", Target: "https://checkip.amazonaws.com"},
		{Name: "http-cf-trace", Kind: "http", Target: "https://www.cloudflare.com/cdn-cgi/trace"},
		{Name: "http-ipip", Kind: "http", Target: "https://myip.ipip.net/json"},
		{Name: "stun-bilibili", Kind: "stun", Target: "stun.chat.bilibili.com:3478"},
		{Name: "stun-google", Kind: "stun", Target: "stun.l.google.com:19302"},
		{Name: "stun-cloudflare", Kind: "stun", Target: "stun.cloudflare.com:3478"},
		{Name: "dns-google-echo", Kind: "dns", Target: "ns1.google.com|o-o.myaddr.l.google.com"},
	}
}

// normalizeEgressTrace fills the documented defaults (house convention: zero
// means default).
func normalizeEgressTrace(cfg *Config) {
	e := &cfg.Probe.Egress
	if e.IntervalSeconds == 0 {
		e.IntervalSeconds = 300
	}
	if len(e.ASNResolvers) == 0 {
		e.ASNResolvers = []string{"223.5.5.5"}
	}
	if len(e.Sources) == 0 {
		e.Sources = DefaultEgressSources()
	}
	t := &cfg.Probe.Trace
	if len(t.Categories) == 0 {
		t.Categories = []string{"external", "quality"}
	}
	if t.IntervalMinutes == 0 {
		t.IntervalMinutes = 30
	}
	if t.MaxTTL == 0 {
		t.MaxTTL = 30
	}
	if t.PerHopMs == 0 {
		t.PerHopMs = 500
	}
	if t.Concurrency == 0 {
		t.Concurrency = 2
	}
}

// validateEgressTrace checks cross-field sanity (zero values pass, like the
// other validators).
func validateEgressTrace(cfg *Config) error {
	e := &cfg.Probe.Egress
	if e.IntervalSeconds != 0 && (e.IntervalSeconds < 60 || e.IntervalSeconds > 86400) {
		return fmt.Errorf("probe.egress.interval_seconds must be between 60 and 86400")
	}
	for _, s := range e.Sources {
		switch s.Kind {
		case "http", "stun", "dns":
		default:
			return fmt.Errorf("probe.egress.sources.%s: kind must be http, stun or dns", s.Name)
		}
		if s.Target == "" || s.Name == "" {
			return fmt.Errorf("probe.egress.sources.%s: every source needs name and target", s.Name)
		}
	}
	t := &cfg.Probe.Trace
	for _, c := range t.Categories {
		if c != "lan" && c != "external" && c != "quality" {
			return fmt.Errorf("probe.trace.categories: unknown category %q (lan|external|quality)", c)
		}
	}
	if t.IntervalMinutes != 0 && t.IntervalMinutes < 5 {
		return fmt.Errorf("probe.trace.interval_minutes must be at least 5")
	}
	if t.MaxTTL != 0 && (t.MaxTTL < 8 || t.MaxTTL > 64) {
		return fmt.Errorf("probe.trace.max_ttl must be between 8 and 64")
	}
	if t.PerHopMs != 0 && (t.PerHopMs < 100 || t.PerHopMs > 3000) {
		return fmt.Errorf("probe.trace.per_hop_ms must be between 100 and 3000")
	}
	if t.Concurrency != 0 && t.Concurrency > 8 {
		return fmt.Errorf("probe.trace.concurrency must be at most 8")
	}
	return nil
}

// DefaultQualityGroups is the shipped default matrix: a domestic primary
// group (dual public resolvers for differential DNS diagnosis, mainstream
// HTTP sites, a 204 endpoint, and a DNS-free direct-IP TCP leg) plus an
// international reference group. Public anycast/service addresses only.
func DefaultQualityGroups() map[string][]ProbeQualityTarget {
	return map[string][]ProbeQualityTarget{
		"domestic": {
			{Name: "quality-dns-ali", Module: "dns", Target: "www.baidu.com", Options: map[string]any{"record": "A", "resolver": "223.5.5.5"}},
			{Name: "quality-dns-dnspod", Module: "dns", Target: "www.baidu.com", Options: map[string]any{"record": "A", "resolver": "119.29.29.29"}},
			{Name: "quality-http-baidu", Module: "http", Target: "https://www.baidu.com"},
			{Name: "quality-http-qq", Module: "http", Target: "https://www.qq.com"},
			{Name: "quality-http-204", Module: "http", Target: "http://connect.rom.miui.com/generate_204", Options: map[string]any{"expected_status": []any{204}}},
			{Name: "quality-tcp-ipdirect", Module: "tcp", Target: "223.5.5.5:53"},
		},
		"international": {
			{Name: "quality-dns-cf", Module: "dns", Target: "www.cloudflare.com", Options: map[string]any{"record": "A", "resolver": "1.1.1.1"}},
			{Name: "quality-http-google204", Module: "http", Target: "http://www.google.com/generate_204", Options: map[string]any{"expected_status": []any{204}}},
		},
	}
}

// normalizeProbe fills the documented defaults for zero-valued fields (the
// "0 means use the default" house convention) and swaps an empty quality
// groups map for the shipped defaults. Runs before validation.
func normalizeProbe(cfg *Config) {
	p := &cfg.Probe
	if p.MaxConcurrency == 0 {
		p.MaxConcurrency = 8
	}
	if p.MaxConcurrency < 1 {
		p.MaxConcurrency = 1
	}
	if p.NotifyFailThreshold == 0 {
		p.NotifyFailThreshold = 3
	}
	if p.NotifyFailThreshold < 1 {
		p.NotifyFailThreshold = 1
	}
	q := &p.Quality
	if q.WindowMinutes == 0 {
		q.WindowMinutes = 15
	}
	if q.IntervalSeconds == 0 {
		q.IntervalSeconds = 120
	}
	if q.HTTPDegradedMs == 0 {
		q.HTTPDegradedMs = 800
	}
	if q.DNSDegradedMs == 0 {
		q.DNSDegradedMs = 300
	}
	if q.OkRateThreshold == 0 {
		q.OkRateThreshold = 0.9
	}
	if len(q.Groups) == 0 {
		q.Groups = DefaultQualityGroups()
	}
	a := &p.Autogen
	if len(a.Services) == 0 {
		a.Services = []string{"http", "https"}
	}
	if a.IntervalSeconds == 0 {
		a.IntervalSeconds = 300
	}
	if a.MaxTargets == 0 {
		a.MaxTargets = 100
	}
	if a.SweepIntervalMinutes == 0 {
		a.SweepIntervalMinutes = 15
	}
	normalizeEgressTrace(cfg)
}

// validateProbe checks cross-field sanity after normalization. Zero values
// pass: Validate can be called on an unnormalized Config (tests construct
// bare structs), and the Load path always normalizes first.
func validateProbe(cfg *Config) error {
	p := &cfg.Probe
	if p.MaxConcurrency > 64 {
		return fmt.Errorf("probe.max_concurrency must be at most 64")
	}
	if p.NotifyFailThreshold > 10 {
		return fmt.Errorf("probe.notify_fail_threshold must be at most 10")
	}
	q := &p.Quality
	if q.WindowMinutes != 0 && (q.WindowMinutes < 5 || q.WindowMinutes > 1440) {
		return fmt.Errorf("probe.quality.window_minutes must be between 5 and 1440")
	}
	if q.IntervalSeconds != 0 && q.IntervalSeconds < 10 {
		return fmt.Errorf("probe.quality.interval_seconds must be at least 10")
	}
	if q.OkRateThreshold < 0 || q.OkRateThreshold > 1 {
		return fmt.Errorf("probe.quality.ok_rate_threshold must be in (0, 1]")
	}
	seen := make(map[string]bool)
	for group, targets := range q.Groups {
		if len(targets) == 0 {
			return fmt.Errorf("probe.quality.groups.%s must hold at least one target", group)
		}
		for _, t := range targets {
			if t.Name == "" || t.Module == "" || t.Target == "" {
				return fmt.Errorf("probe.quality.groups.%s: every target needs name, module and target", group)
			}
			if seen[t.Name] {
				return fmt.Errorf("probe.quality target name %q appears in more than one group", t.Name)
			}
			seen[t.Name] = true
		}
	}
	a := &p.Autogen
	if a.Enabled {
		if a.IntervalSeconds != 0 && a.IntervalSeconds < 10 {
			return fmt.Errorf("probe.autogen.interval_seconds must be at least 10")
		}
		if a.MaxTargets != 0 && (a.MaxTargets < 1 || a.MaxTargets > 1000) {
			return fmt.Errorf("probe.autogen.max_targets must be between 1 and 1000")
		}
	}
	return validateEgressTrace(cfg)
}
