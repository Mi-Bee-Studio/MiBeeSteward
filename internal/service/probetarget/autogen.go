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
	"strings"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// AutogenService is the discover-then-probe reconciler (#606): it turns the
// devices' detected_services identities (the JSON both the agent-report
// bridge and the local/passive identify populate) into device-bound probe
// targets (source=auto) and follows their lifecycle - a service that leaves
// the scan disables its target, a reappearance re-enables it. Manual targets
// are never touched. Default OFF; bounded by probe.autogen.max_targets.
type AutogenService struct {
	queries *db.Queries
	cfg     config.ProbeAutogenConfig
	// settings is the settings-center overlay (nil ⇒ YAML config only); the
	// probe.autogen row carries the web-editable switches, merged per sweep.
	settings SettingsGetter
	logger   *slog.Logger
}

func NewAutogenService(queries *db.Queries, cfg config.ProbeAutogenConfig, logger *slog.Logger) *AutogenService {
	if logger == nil {
		logger = slog.Default()
	}
	// Defend the documented defaults (normalizeProbe's values) so a bare
	// struct behaves like a loaded config.
	if len(cfg.Services) == 0 {
		cfg.Services = []string{"http", "https"}
	}
	if cfg.IntervalSeconds == 0 {
		cfg.IntervalSeconds = 300
	}
	if cfg.MaxTargets == 0 {
		cfg.MaxTargets = 100
	}
	if cfg.SweepIntervalMinutes == 0 {
		cfg.SweepIntervalMinutes = 15
	}
	return &AutogenService{queries: queries, cfg: cfg, logger: logger}
}

// SetSettingsSource wires the settings-center overlay (nil-safe, chainable).
// Every sweep re-resolves the effective policy, so flipping 设置 → 拨测's
// autogen switch takes effect on the next sweep — and RouteSweep lets the
// settings subscriber trigger that sweep immediately.
func (s *AutogenService) SetSettingsSource(g SettingsGetter) *AutogenService {
	s.settings = g
	return s
}

// effective resolves overlay policy ?? startup YAML config.
func (s *AutogenService) effective() config.ProbeAutogenConfig {
	if s.settings != nil {
		var p config.ProbeAutogenPolicy
		if s.settings.Get(SettingKeyAutogen, &p) {
			return p.Apply(s.cfg)
		}
	}
	return s.cfg
}

// autogenName is the deterministic target name for one (device, service,
// port): stable across sweeps, unique by construction.
func autogenName(deviceID int64, service string, port int64) string {
	return fmt.Sprintf("auto-d%d-%s-%d", deviceID, service, port)
}

// autogenPlan derives module/target from a discovered service identity:
// http/https probe their URL semantics, every other TCP service gets a
// plain port probe.
func autogenPlan(service string, ip string, port int64) (module, target string) {
	switch service {
	case "http":
		return "http", fmt.Sprintf("http://%s:%d/", ip, port)
	case "https":
		return "http", fmt.Sprintf("https://%s:%d/", ip, port)
	default:
		return "tcp", fmt.Sprintf("%s:%d", ip, port)
	}
}

// Sweep reconciles once. Called at startup, every
// probe.autogen.sweep_interval_minutes, and on demand from the settings
// subscriber / the autogen-sweep API (设置 → 拨测, probes page empty state).
func (s *AutogenService) Sweep(ctx context.Context) (created, enabled, disabled int, err error) {
	cfg := s.effective()
	existing, err := s.queries.ListProbeTargets(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("autogen: list targets: %w", err)
	}
	autoByName := make(map[string]db.ProbeTarget)
	autoCount := 0
	for _, t := range existing {
		if t.Source == domain.ProbeSourceAuto {
			autoByName[t.Name] = t
			autoCount++
		}
	}

	if !cfg.Enabled {
		// Policy turned off: park the auto population (keep rows + history).
		for _, t := range autoByName {
			if t.Enabled == 1 {
				if derr := s.queries.ToggleProbeTargetEnabled(ctx, db.ToggleProbeTargetEnabledParams{Enabled: 0, ID: t.ID}); derr != nil {
					return 0, 0, disabled, fmt.Errorf("autogen: park %s: %w", t.Name, derr)
				}
				disabled++
			}
		}
		if disabled > 0 {
			s.logger.Info("probe autogen: disabled (config off), auto targets parked", "targets", disabled)
		}
		return 0, 0, disabled, nil
	}

	services, err := s.queries.ListDevicesForProbeAutogen(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("autogen: list devices: %w", err)
	}
	nets, err := s.queries.ListNetworks(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("autogen: list networks: %w", err)
	}
	agentByNetwork := make(map[int64]string, len(nets))
	for _, n := range nets {
		if n.AgentID != nil && strings.TrimSpace(*n.AgentID) != "" {
			agentByNetwork[n.ID] = strings.TrimSpace(*n.AgentID)
		}
	}
	serviceFilter := make(map[string]bool, len(cfg.Services))
	for _, svc := range cfg.Services {
		serviceFilter[strings.ToLower(strings.TrimSpace(svc))] = true
	}
	typeFilter := make(map[string]bool, len(cfg.DeviceTypes))
	for _, dt := range cfg.DeviceTypes {
		typeFilter[dt] = true
	}

	// Vantage: probe a LAN device FROM its own network's agent when there is
	// one (probing across the WAN back-haul would measure the tunnel, not
	// the service), else from the center.
	vantageFor := func(networkID *int64) string {
		if networkID == nil {
			return domain.ProbeVantageCenter
		}
		if agent, ok := agentByNetwork[*networkID]; ok {
			return domain.ProbeVantageAgentPrefix + agent
		}
		return domain.ProbeVantageCenter
	}

	desired := make(map[string]bool)
	for _, d := range services {
		if len(typeFilter) > 0 && !typeFilter[d.Type] {
			continue
		}
		if d.IpAddress == "" {
			continue
		}
		// detected_services JSON: [{"name":"http","port":8080,"protocol":"tcp"},...]
		var svcs []struct {
			Name string `json:"name"`
			Port int64  `json:"port"`
		}
		if err := json.Unmarshal([]byte(d.DetectedServices), &svcs); err != nil {
			continue
		}
		for _, svc := range svcs {
			name := strings.ToLower(svc.Name)
			if len(serviceFilter) > 0 && !serviceFilter[name] {
				continue
			}
			// Portless identities (hostname-derived, e.g. miot on port 0)
			// have nothing to dial.
			if svc.Port <= 0 {
				continue
			}
			targetName := autogenName(d.ID, name, svc.Port)
			desired[targetName] = true
			module, target := autogenPlan(name, d.IpAddress, svc.Port)

			if prev, ok := autoByName[targetName]; ok {
				// Follow drift: the service may have moved port semantics; the
				// vantage may have changed with the device's network. Re-enable
				// a target that was parked when the service had vanished.
				needsUpdate := prev.Module != module || prev.Target != target
				if needsUpdate {
					if _, uerr := s.queries.UpdateProbeTarget(ctx, db.UpdateProbeTargetParams{
						Name: prev.Name, Module: module, Target: target,
						IntervalSeconds: prev.IntervalSeconds, TimeoutSeconds: prev.TimeoutSeconds,
						Enabled: prev.Enabled, Notes: prev.Notes, Vantage: vantageFor(d.NetworkID),
						Options: prev.Options, DeviceID: &d.ID, ID: prev.ID,
					}); uerr != nil {
						return created, enabled, disabled, fmt.Errorf("autogen: update %s: %w", targetName, uerr)
					}
				}
				if prev.Enabled == 0 {
					if eerr := s.queries.ToggleProbeTargetEnabled(ctx, db.ToggleProbeTargetEnabledParams{Enabled: 1, ID: prev.ID}); eerr != nil {
						return created, enabled, disabled, fmt.Errorf("autogen: re-enable %s: %w", targetName, eerr)
					}
					enabled++
				}
				continue
			}

			if autoCount >= cfg.MaxTargets {
				s.logger.Warn("probe autogen: max_targets reached, skipping new services",
					"cap", cfg.MaxTargets, "skipped_from", targetName)
				break
			}
			deviceID := d.ID
			if _, cerr := s.queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
				Name: targetName, Module: module, Target: target,
				IntervalSeconds: int64(cfg.IntervalSeconds), TimeoutSeconds: 10,
				Enabled: 1, Notes: "auto-generated from a discovered service (#606)",
				Vantage: vantageFor(d.NetworkID), DeviceID: &deviceID,
				Source: domain.ProbeSourceAuto,
			}); cerr != nil {
				return created, enabled, disabled, fmt.Errorf("autogen: create %s: %w", targetName, cerr)
			}
			autoCount++
			created++
		}
	}

	// Services that left the scan park their targets (kept for history, the
	// UI marks them; a reappearance re-enables above).
	for name, t := range autoByName {
		if desired[name] || t.Enabled == 0 {
			continue
		}
		if derr := s.queries.ToggleProbeTargetEnabled(ctx, db.ToggleProbeTargetEnabledParams{Enabled: 0, ID: t.ID}); derr != nil {
			return created, enabled, disabled, fmt.Errorf("autogen: park %s: %w", name, derr)
		}
		disabled++
	}

	if cfg.EffectiveMeshEnabled() {
		mc, me, md, merr := s.sweepMesh(ctx)
		if merr != nil {
			return created, enabled, disabled, merr
		}
		created += mc
		enabled += me
		disabled += md
	}

	if created+enabled+disabled > 0 {
		s.logger.Info("probe autogen: sweep", "created", created, "enabled", enabled, "disabled", disabled, "auto_total", autoCount)
	}
	return created, enabled, disabled, nil
}

// meshTargetPrefix marks every mesh-matrix row (#747). Mesh targets are
// source='system' (they land in the quality category and never appear as
// user-created rows), icmp with the burst shape so loss/jitter ride the
// matrix from day one.
const meshTargetPrefix = "mesh-"

// meshOptionsJSON is every mesh target's option block: a 10-echo burst at
// the 20ms default gap. A shared literal (not a marshaled struct) keeps the
// desired-state comparison trivial.
const meshOptionsJSON = `{"burst_count":10}`

// sweepMesh reconciles the site-to-site matrix (#747): center -> every agent
// with a known source address, and every ordered agent pair a -> b. Rows are
// keyed by name (mesh-center-to-{agent} / mesh-{src}-to-{dst}), source
// 'system'; an agent that stops reporting parks its rows (kept for history,
// a reappearance re-enables). Returns the sweep counters (created, enabled,
// disabled).
func (s *AutogenService) sweepMesh(ctx context.Context) (created, enabled, disabled int, err error) {
	fleet, ferr := s.queries.ListAgentStatus(ctx)
	if ferr != nil {
		return 0, 0, 0, fmt.Errorf("autogen: mesh list agents: %w", ferr)
	}
	type peer struct{ agentID, ip string }
	var agents []peer
	for _, a := range fleet {
		if ip := strings.TrimSpace(a.LastSourceIp); ip != "" {
			agents = append(agents, peer{strings.TrimSpace(a.AgentID), ip})
		}
	}

	existing, lerr := s.queries.ListProbeTargets(ctx)
	if lerr != nil {
		return 0, 0, 0, fmt.Errorf("autogen: mesh list targets: %w", lerr)
	}
	meshByName := make(map[string]db.ProbeTarget)
	for _, t := range existing {
		if strings.HasPrefix(t.Name, meshTargetPrefix) {
			meshByName[t.Name] = t
		}
	}

	desired := make(map[string]bool)
	want := func(name, vantage, target string) {
		desired[name] = true
		if prev, ok := meshByName[name]; ok {
			if prev.Target != target || prev.Vantage != vantage {
				if _, uerr := s.queries.UpdateProbeTarget(ctx, db.UpdateProbeTargetParams{
					Name: prev.Name, Module: "icmp", Target: target,
					IntervalSeconds: prev.IntervalSeconds, TimeoutSeconds: prev.TimeoutSeconds,
					Enabled: prev.Enabled, Notes: prev.Notes, Vantage: vantage,
					Options: meshOptionsJSON, ID: prev.ID,
				}); uerr != nil {
					s.logger.Warn("probe autogen: mesh update failed", "name", name, "error", uerr)
				}
			}
			if prev.Enabled == 0 {
				if eerr := s.queries.ToggleProbeTargetEnabled(ctx, db.ToggleProbeTargetEnabledParams{Enabled: 1, ID: prev.ID}); eerr == nil {
					enabled++
				}
			}
			return
		}
		if _, cerr := s.queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
			Name: name, Module: "icmp", Target: target,
			IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: 1,
			Notes:   "auto-generated site-to-site matrix leg (#747)",
			Vantage: vantage, Options: meshOptionsJSON,
			Source: domain.ProbeSourceSystem,
		}); cerr != nil {
			s.logger.Warn("probe autogen: mesh create failed", "name", name, "error", cerr)
			return
		}
		created++
	}

	// Center -> each agent.
	for _, a := range agents {
		want(meshTargetPrefix+"center-to-"+a.agentID, domain.ProbeVantageCenter, a.ip)
	}
	// Each ordered agent pair a -> b (a executes the probe).
	for _, src := range agents {
		for _, dst := range agents {
			if src.agentID == dst.agentID {
				continue
			}
			want(meshTargetPrefix+src.agentID+"-to-"+dst.agentID,
				domain.ProbeVantageAgentPrefix+src.agentID, dst.ip)
		}
	}

	// Agents gone (or addresses lost) park their rows.
	for name, t := range meshByName {
		if desired[name] || t.Enabled == 0 {
			continue
		}
		if derr := s.queries.ToggleProbeTargetEnabled(ctx, db.ToggleProbeTargetEnabledParams{Enabled: 0, ID: t.ID}); derr != nil {
			s.logger.Warn("probe autogen: mesh park failed", "name", name, "error", derr)
			continue
		}
		disabled++
	}
	return created, enabled, disabled, nil
}

// StartSweepLoop runs the sweep at the configured cadence until stop.
func (s *AutogenService) StartSweepLoop(ctx context.Context, stop <-chan struct{}) {
	interval := s.cfg.SweepIntervalMinutes
	if interval <= 0 {
		interval = 15
	}
	s.sweepQuiet(ctx)
	ticker := time.NewTicker(time.Duration(interval) * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.sweepQuiet(ctx)
		}
	}
}

func (s *AutogenService) sweepQuiet(ctx context.Context) {
	if _, _, _, err := s.Sweep(ctx); err != nil {
		s.logger.Warn("probe autogen: sweep failed", "error", err)
	}
}
