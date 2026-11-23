// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func intPtr(v int) *int { return &v }

// TestNormalizeProbe pins the documented-default fill for zero values and
// the shipped default quality matrix.
func TestNormalizeProbe(t *testing.T) {
	cfg := &Config{}
	normalizeProbe(cfg)
	p := &cfg.Probe
	require.Equal(t, 8, p.MaxConcurrency)
	require.Equal(t, 3, p.NotifyFailThreshold, "notify_fail_threshold default")
	require.Equal(t, 15, p.Quality.WindowMinutes)
	require.Equal(t, 120, p.Quality.IntervalSeconds)
	require.Equal(t, 800, p.Quality.HTTPDegradedMs)
	require.Equal(t, 300, p.Quality.DNSDegradedMs)
	require.InDelta(t, 0.9, p.Quality.OkRateThreshold, 0.0001)
	require.NotNil(t, p.Quality.Enabled)
	require.True(t, *p.Quality.Enabled, "absent key = shipped default on (upgrade-keep configs self-heal)")
	require.False(t, p.Autogen.Enabled, "autogen stays off unless explicitly enabled")
	require.Equal(t, []string{"http", "https"}, p.Autogen.Services)
	require.Equal(t, 100, p.Autogen.MaxTargets)

	// The web-editable policies merge field-wise onto a config copy; nil
	// fields are no-ops (the settings overlay stores only the switches).
	on, off := true, false
	qcfg := ProbeQualityConfig{WindowMinutes: 15}
	qcfg = ProbeQualityPolicy{Enabled: &on}.Apply(qcfg)
	require.True(t, qcfg.EffectiveEnabled())
	require.Equal(t, 15, qcfg.WindowMinutes, "non-switch fields untouched")
	qcfg = ProbeQualityPolicy{Enabled: &off}.Apply(qcfg)
	require.False(t, qcfg.EffectiveEnabled())

	acfg := ProbeAutogenConfig{Enabled: false, MaxTargets: 100, IntervalSeconds: 300}
	acfg = ProbeAutogenPolicy{Enabled: &on}.Apply(acfg)
	require.True(t, acfg.Enabled)
	require.Equal(t, 100, acfg.MaxTargets, "nil max_targets untouched")
	acfg = ProbeAutogenPolicy{MaxTargets: intPtr(50), IntervalSeconds: intPtr(120)}.Apply(acfg)
	require.Equal(t, 50, acfg.MaxTargets)
	require.Equal(t, 120, acfg.IntervalSeconds)
	require.True(t, acfg.Enabled, "nil enabled untouched")

	groups := p.Quality.Groups
	require.NotEmpty(t, groups["domestic"], "default domestic group present")
	require.NotEmpty(t, groups["international"], "default reference group present")
	// The differential-DNS + DNS-free direct legs the verdict chain relies on.
	require.Len(t, groups["domestic"], 6)
	mods := map[string]int{}
	for _, tgt := range groups["domestic"] {
		mods[tgt.Module]++
	}
	require.Equal(t, 2, mods["dns"])
	require.Equal(t, 3, mods["http"])
	require.Equal(t, 1, mods["tcp"])

	// A provided groups map is kept verbatim.
	cfg = &Config{}
	cfg.Probe.Quality.Groups = map[string][]ProbeQualityTarget{
		"mine": {{Name: "q1", Module: "http", Target: "https://x.example/"}},
	}
	normalizeProbe(cfg)
	require.Len(t, cfg.Probe.Quality.Groups, 1)
	require.Contains(t, cfg.Probe.Quality.Groups, "mine")

	// notify_fail_threshold: 0 → default 3, negative clamps to 1, explicit
	// values are kept.
	cfg = &Config{}
	normalizeProbe(cfg)
	require.Equal(t, 3, cfg.Probe.NotifyFailThreshold)
	cfg.Probe.NotifyFailThreshold = -1
	normalizeProbe(cfg)
	require.Equal(t, 1, cfg.Probe.NotifyFailThreshold)
	cfg.Probe.NotifyFailThreshold = 5
	normalizeProbe(cfg)
	require.Equal(t, 5, cfg.Probe.NotifyFailThreshold)
}

// validProbeConfig builds the minimal center-mode Config that passes the
// shared Validate (JWT secret) so the probe sub-validator can be exercised.
func validProbeConfig() *Config {
	return &Config{Auth: AuthConfig{JWTSecret: "a-32-char-secret-for-testing-purposes"}}
}

// TestValidateProbe pins the cross-field rules: duplicate matrix names are
// rejected, and unnormalized zero values pass (bare structs hit Validate in
// tests; the Load path normalizes first).
func TestValidateProbe(t *testing.T) {
	require.NoError(t, Validate(validProbeConfig()), "zero config is valid unnormalized")

	// notify_fail_threshold ceiling.
	badThreshold := validProbeConfig()
	badThreshold.Probe.NotifyFailThreshold = 11
	require.ErrorContains(t, Validate(badThreshold), "notify_fail_threshold")

	// agent_fleet.offline_threshold_minutes range (0 = default via Load).
	badOffline := validProbeConfig()
	badOffline.AgentFleet.OfflineThresholdMinutes = 1441
	require.ErrorContains(t, Validate(badOffline), "offline_threshold_minutes")

	bad := validProbeConfig()
	bad.Probe.MaxConcurrency = 65
	require.ErrorContains(t, Validate(bad), "max_concurrency")

	bad = validProbeConfig()
	bad.Probe.Quality.WindowMinutes = 3
	require.ErrorContains(t, Validate(bad), "window_minutes")

	dup := validProbeConfig()
	dup.Probe.Quality.Groups = map[string][]ProbeQualityTarget{
		"a": {{Name: "same", Module: "http", Target: "https://a.example/"}},
		"b": {{Name: "same", Module: "tcp", Target: "203.0.113.9:80"}},
	}
	require.ErrorContains(t, Validate(dup), "more than one group")

	incomplete := validProbeConfig()
	incomplete.Probe.Quality.Groups = map[string][]ProbeQualityTarget{
		"a": {{Name: "x", Module: "http"}},
	}
	require.ErrorContains(t, Validate(incomplete), "name, module and target")
}

// TestValidateEgressTrace pins the egress/path config validation branches
// (#718/#719): source kinds, category names, and each numeric range.
func TestValidateEgressTrace(t *testing.T) {
	newCfg := func(mutate func(*Config)) *Config {
		c := validProbeConfig()
		mutate(c)
		return c
	}
	require.NoError(t, Validate(newCfg(func(*Config) {})))

	badKind := newCfg(func(c *Config) {
		c.Probe.Egress.Sources = []ProbeEgressSource{{Name: "x", Kind: " carrier-pigeon", Target: "y"}}
	})
	badKind.Probe.Egress.Sources[0].Kind = "carrier-pigeon"
	require.ErrorContains(t, Validate(badKind), "kind must be http, stun or dns")

	noTarget := newCfg(func(c *Config) {
		c.Probe.Egress.Sources = []ProbeEgressSource{{Name: "x", Kind: "http"}}
	})
	require.ErrorContains(t, Validate(noTarget), "every source needs name and target")

	for secs, want := range map[int]string{59: "between 60 and 86400", 86401: "between 60 and 86400"} {
		bad := newCfg(func(c *Config) { c.Probe.Egress.IntervalSeconds = secs })
		require.ErrorContains(t, Validate(bad), want)
	}

	badCat := newCfg(func(c *Config) { c.Probe.Trace.Categories = []string{"dmz"} })
	require.ErrorContains(t, Validate(badCat), "unknown category")

	badInterval := newCfg(func(c *Config) { c.Probe.Trace.IntervalMinutes = 4 })
	require.ErrorContains(t, Validate(badInterval), "interval_minutes")

	badTTL := newCfg(func(c *Config) { c.Probe.Trace.MaxTTL = 7 })
	require.ErrorContains(t, Validate(badTTL), "max_ttl")

	badHop := newCfg(func(c *Config) { c.Probe.Trace.PerHopMs = 99 })
	require.ErrorContains(t, Validate(badHop), "per_hop_ms")

	badConc := newCfg(func(c *Config) { c.Probe.Trace.Concurrency = 9 })
	require.ErrorContains(t, Validate(badConc), "concurrency")
}

// TestNormalizeEgressTrace pins the documented defaults.
func TestNormalizeEgressTrace(t *testing.T) {
	c := validProbeConfig()
	normalizeProbe(c)
	require.Equal(t, 300, c.Probe.Egress.IntervalSeconds)
	require.Equal(t, []string{"223.5.5.5"}, c.Probe.Egress.ASNResolvers)
	require.NotEmpty(t, c.Probe.Egress.Sources)
	require.Equal(t, []string{"external", "quality"}, c.Probe.Trace.Categories)
	require.Equal(t, 30, c.Probe.Trace.IntervalMinutes)
	require.Equal(t, 30, c.Probe.Trace.MaxTTL)
	require.Equal(t, 500, c.Probe.Trace.PerHopMs)
	require.Equal(t, 2, c.Probe.Trace.Concurrency)
}

// TestDefaultSTUNServers pins the shipped list and the liveness rule behind
// the 2026-11-23 swap: endpoints were re-measured from two vantages (63/62
// LANs, five probes each). stun.qq.com and stun.miwifi.com answered 0/5 at
// both and must never return without a fresh measurement; the P2P platform
// dropped the Tencent endpoint from production on 2026-11-07
// (MiBeeP2PServer#119) while Steward kept shipping it.
func TestDefaultSTUNServers(t *testing.T) {
	servers := DefaultSTUNServers()
	require.Len(t, servers, 5)
	endpoints := make([]string, 0, len(servers))
	for _, s := range servers {
		endpoints = append(endpoints, s.Endpoint)
		require.True(t, s.Builtin, "%s must be builtin", s.Endpoint)
		require.True(t, s.Enabled, "%s ships enabled", s.Endpoint)
		require.NotEmpty(t, s.Label, "%s needs a label", s.Endpoint)
	}
	require.NotContains(t, endpoints, "stun.qq.com:3478", "dead since at least 2026-11-07 (0/5 on both rigs)")
	require.NotContains(t, endpoints, "stun.miwifi.com:3478", "dead on both rigs (0/5)")
	for _, want := range []string{
		"stun.cloudflare.com:3478",
		"stun.l.google.com:19302",
		"stun.nextcloud.com:443",
		"stun.chat.bilibili.com:3478", // fastest domestic source: 4/5 at ~45ms
		"stun.antisip.com:3478",       // steadiest international source: 5/5
	} {
		require.Contains(t, endpoints, want)
	}
}

// TestReconcileSTUNServers pins the overlay upgrade path. probe.nat lives in
// system_settings (not YAML), so a list stored before a builtin swap is only
// fixable at read time — otherwise the old rows keep probing dead endpoints
// and the PUT builtin-must-be-present gate rejects every later save.
func TestReconcileSTUNServers(t *testing.T) {
	// Pre-swap overlay: the two retired builtins plus two still-shipped ones
	// (one disabled by the operator) and a user row.
	stale := []ProbeSTUNServer{
		{Endpoint: "stun.cloudflare.com:3478", Label: "Cloudflare", Builtin: true, Enabled: false},
		{Endpoint: "stun.qq.com:3478", Label: "Tencent", Builtin: true, Enabled: true},
		{Endpoint: "stun.miwifi.com:3478", Label: "Xiaomi", Builtin: true, Enabled: true},
		{Endpoint: "stun.l.google.com:19302", Label: "Google", Builtin: true, Enabled: true},
		{Endpoint: "my-stun.example.com:3478", Label: "self-hosted", Builtin: false, Enabled: true},
	}
	got := ReconcileSTUNServers(stale)
	byEndpoint := map[string]ProbeSTUNServer{}
	for _, s := range got {
		require.False(t, byEndpoint[s.Endpoint].Endpoint != "", "duplicate %s", s.Endpoint)
		byEndpoint[s.Endpoint] = s
	}
	require.NotContains(t, byEndpoint, "stun.qq.com:3478", "retired builtin dropped")
	require.NotContains(t, byEndpoint, "stun.miwifi.com:3478", "retired builtin dropped")
	require.False(t, byEndpoint["stun.cloudflare.com:3478"].Enabled, "operator's disable survives")
	require.Equal(t, "Cloudflare", byEndpoint["stun.cloudflare.com:3478"].Label, "shipped label wins")
	require.True(t, byEndpoint["stun.chat.bilibili.com:3478"].Builtin, "new builtin appended")
	require.True(t, byEndpoint["stun.antisip.com:3478"].Builtin, "new builtin appended")
	require.True(t, byEndpoint["my-stun.example.com:3478"].Enabled, "user row untouched")
	require.False(t, byEndpoint["my-stun.example.com:3478"].Builtin, "user row stays custom")
	require.Len(t, got, 6, "5 builtins + 1 user row")

	// A user-added row that happens to name a retired endpoint survives as a
	// user row — reconciliation never eats user data.
	reAdded := ReconcileSTUNServers([]ProbeSTUNServer{
		{Endpoint: "stun.qq.com:3478", Label: "my tencent", Builtin: false, Enabled: true},
	})
	found := false
	for _, s := range reAdded {
		if s.Endpoint == "stun.qq.com:3478" {
			found = true
			require.False(t, s.Builtin)
		}
	}
	require.True(t, found, "user re-add of a retired endpoint is preserved")

	// Idempotent: the shipped list reconciles to itself.
	require.Equal(t, DefaultSTUNServers(), ReconcileSTUNServers(DefaultSTUNServers()))

	// NormalizeProbeNAT routes every non-empty stored list through it.
	cfg := ProbeNATConfig{Servers: stale}
	NormalizeProbeNAT(&cfg)
	for _, s := range cfg.Servers {
		require.NotEqual(t, "stun.qq.com:3478", s.Endpoint)
	}
	empty := ProbeNATConfig{}
	NormalizeProbeNAT(&empty)
	require.Equal(t, DefaultSTUNServers(), empty.Servers)
}
