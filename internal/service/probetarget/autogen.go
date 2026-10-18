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
	logger  *slog.Logger
}

func NewAutogenService(queries *db.Queries, cfg config.ProbeAutogenConfig, logger *slog.Logger) *AutogenService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AutogenService{queries: queries, cfg: cfg, logger: logger}
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

// Sweep reconciles once. Called at startup and every
// probe.autogen.sweep_interval_minutes.
func (s *AutogenService) Sweep(ctx context.Context) (created, enabled, disabled int, err error) {
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

	if !s.cfg.Enabled {
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
	serviceFilter := make(map[string]bool, len(s.cfg.Services))
	for _, svc := range s.cfg.Services {
		serviceFilter[strings.ToLower(strings.TrimSpace(svc))] = true
	}
	typeFilter := make(map[string]bool, len(s.cfg.DeviceTypes))
	for _, dt := range s.cfg.DeviceTypes {
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

			if autoCount >= s.cfg.MaxTargets {
				s.logger.Warn("probe autogen: max_targets reached, skipping new services",
					"cap", s.cfg.MaxTargets, "skipped_from", targetName)
				break
			}
			deviceID := d.ID
			if _, cerr := s.queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
				Name: targetName, Module: module, Target: target,
				IntervalSeconds: int64(s.cfg.IntervalSeconds), TimeoutSeconds: 10,
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
	if created+enabled+disabled > 0 {
		s.logger.Info("probe autogen: sweep", "created", created, "enabled", enabled, "disabled", disabled, "auto_total", autoCount)
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
