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
	require.False(t, p.Quality.Enabled, "quality is opt-in via yaml, not defaulted on")
	require.False(t, p.Autogen.Enabled, "autogen stays off unless explicitly enabled")
	require.Equal(t, []string{"http", "https"}, p.Autogen.Services)
	require.Equal(t, 100, p.Autogen.MaxTargets)

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
