// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package archive

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// Periodic-pattern learner (#664).
//
// A device that keeps returning on a stable cycle — the canonical case is one
// that appears online once a month — must not be archived over and over. The
// learner builds its evidence from the archive lifecycle event stream: every
// "appearance" (an auto/pattern restore, or an online blip on an archived
// device) is a return data point; the archived events in between confirm the
// departures. Manual actions (manual restores, pin changes) are deliberately
// EXCLUDED from the evidence: they express human intent, not device behavior.
//
// Recognition gates (all must hold):
//
//	learner enabled          archive.smart.disabled = false
//	history span ≥ 60d       first→last appearance covers min_history_days
//	threshold < 30d          effective threshold (override > global) below
//	                         max_threshold_days — a month-plus threshold never
//	                         crosses a monthly cycle anyway
//	≥2 stable intervals      ≥3 appearances, consecutive gaps within ±25% of
//	                         their median
//
// On recognition the device is flagged periodic (devices.periodic +
// periodic_cycle_days); periodic devices are exempt from auto-archive, and a
// recognized device still IN the archive is auto-restored (trigger=pattern).
// The pattern auto-expires once the device has been absent longer than 2x the
// learned cycle, so a periodic flag can never become a permanent stay-out.

const (
	// patternMinAppearances is the minimum appearance count for a pattern:
	// 3 appearances yield 2 consecutive intervals — the smallest series that
	// can show a cycle rather than a coincidence.
	patternMinAppearances = 3
	// patternIntervalTolerance bounds interval stability: every consecutive
	// gap must sit within ±25% of the median gap.
	patternIntervalTolerance = 0.25
)

// appearance extracts the timestamps the learner treats as return evidence
// from a device's event series: auto/pattern restores and online blips, in
// ascending order. Manual-triggered rows are skipped (human intent).
func appearance(events []db.ListDeviceArchiveEventsRow) []time.Time {
	var out []time.Time
	for _, e := range events {
		if e.TriggeredBy == TriggerManual {
			continue
		}
		switch e.Event {
		case EventRestored, EventOnlineBlip:
			out = append(out, e.OccurredAt)
		}
	}
	return out
}

// recognize evaluates an appearance series. ok=true means a stable cycle of
// cycleDays was identified over a sufficiently long history span AND the
// pattern is still live: the most recent appearance must sit within 2x the
// learned cycle of now, so a stale historical rhythm cannot keep exempting a
// device that has stopped returning (and a freshly expired pattern cannot be
// instantly re-learned — the device must actually come back once more).
func recognize(cfg config.ArchiveConfig, apps []time.Time, now time.Time) (cycleDays float64, ok bool) {
	if len(apps) < patternMinAppearances {
		return 0, false
	}
	span := apps[len(apps)-1].Sub(apps[0])
	if span < time.Duration(cfg.Smart.MinHistoryDays)*24*time.Hour {
		return 0, false
	}
	gaps := make([]float64, 0, len(apps)-1)
	for i := 1; i < len(apps); i++ {
		gaps = append(gaps, apps[i].Sub(apps[i-1]).Hours())
	}
	sorted := append([]float64(nil), gaps...)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]
	lo, hi := median*(1-patternIntervalTolerance), median*(1+patternIntervalTolerance)
	for _, g := range gaps {
		if g < lo || g > hi {
			return 0, false
		}
	}
	if now.Sub(apps[len(apps)-1]) > time.Duration(2*median*float64(time.Hour)) {
		return 0, false // pattern went stale: last return is older than 2x the cycle
	}
	return median / 24, true
}

// exemptionActive reports whether the smart exemption can apply at this
// threshold: learner on AND effective threshold below the cap.
func exemptionActive(cfg config.ArchiveConfig, thresholdDays int) bool {
	return !cfg.Smart.Disabled && thresholdDays < cfg.Smart.MaxThresholdDays
}

// lastAppearance returns the newest appearance timestamp in the series.
func lastAppearance(events []db.ListDeviceArchiveEventsRow) (time.Time, bool) {
	apps := appearance(events)
	if len(apps) == 0 {
		return time.Time{}, false
	}
	return apps[len(apps)-1], true
}

// patternSweep runs before auto-archive each tick:
//
//  1. expiry: periodic devices absent longer than 2x their learned cycle
//     (and currently offline) lose the flag — they become ordinary devices
//     again, subject to normal archiving.
//  2. learn-while-archived: for every archived device, a newly recognized
//     pattern sets the periodic flag and auto-restores the device out of the
//     archive (it has proven it returns; keeping it filed would hide a live,
//     if intermittent, asset).
//
// The learn-at-decision-point path (candidate about to be archived → pattern
// recognized → set flag + skip) lives in autoArchive, which shares
// evaluateDevice below.
func (s *Service) patternSweep(ctx context.Context, cfg config.ArchiveConfig) {
	now := time.Now()

	// 1. Expiry pass.
	states, err := s.queries.ListPeriodicDeviceStates(ctx)
	if err != nil {
		s.logger.Warn("archive: pattern expiry select failed", "error", err)
		return
	}
	for _, st := range states {
		if ctx.Err() != nil {
			return
		}
		events, err := s.queries.ListDeviceArchiveEvents(ctx, st.ID)
		if err != nil {
			s.logger.Warn("archive: pattern event load failed", "device_id", st.ID, "error", err)
			continue
		}
		last, ok := lastAppearance(events)
		absentLimit := time.Duration(2 * st.PeriodicCycleDays * 24 * float64(time.Hour))
		if !ok || st.Status != "offline" || now.Sub(last) <= absentLimit {
			continue // currently present, or absent within the 2x window
		}
		if err := s.clearPattern(ctx, st.ID, now, "absent_beyond_2x_cycle"); err != nil {
			s.logger.Warn("archive: pattern clear failed", "device_id", st.ID, "error", err)
		}
	}

	// 2. Learn-while-archived pass.
	if cfg.Smart.Disabled {
		return
	}
	archived, err := s.queries.ListArchivedDeviceOverrides(ctx)
	if err != nil {
		s.logger.Warn("archive: archived-device select failed", "error", err)
		return
	}
	for _, ad := range archived {
		if ctx.Err() != nil {
			return
		}
		threshold := cfg.OfflineDays
		if ad.OfflineDaysOverride > 0 {
			threshold = int(ad.OfflineDaysOverride)
		}
		if !exemptionActive(cfg, threshold) {
			continue // this device's threshold is at/above the cap: no exemption
		}
		events, err := s.queries.ListDeviceArchiveEvents(ctx, ad.ID)
		if err != nil {
			s.logger.Warn("archive: pattern event load failed", "device_id", ad.ID, "error", err)
			continue
		}
		cycle, ok := recognize(cfg, appearance(events), now)
		if !ok {
			continue
		}
		if err := s.setPeriodic(ctx, ad.ID, cycle, now); err != nil {
			s.logger.Warn("archive: pattern set failed", "device_id", ad.ID, "error", err)
			continue
		}
		if _, err := s.queries.RestoreArchivedDevice(ctx, db.RestoreArchivedDeviceParams{
			UpdatedAt: now, ID: ad.ID,
		}); err != nil {
			s.logger.Warn("archive: pattern restore failed", "device_id", ad.ID, "error", err)
			continue
		}
		detail, _ := json.Marshal(map[string]any{"cycle_days": cycle})
		if err := s.insertEvent(ctx, ad.ID, EventRestored, TriggerPattern, string(detail), now); err != nil {
			s.logger.Warn("archive: event write failed", "device_id", ad.ID, "error", err)
		}
		s.logger.Info("archive: periodic pattern recognized, device restored",
			"device_id", ad.ID, "cycle_days", cycle)
	}
}

// evaluateDevice runs the learn-at-decision-point check for a single
// auto-archive candidate: returns true when the device should be EXEMPT
// (pattern just recognized, or already flagged periodic with the exemption
// still applicable at this threshold).
func (s *Service) evaluateDevice(ctx context.Context, id int64, thresholdDays int, periodic bool, cfg config.ArchiveConfig, now time.Time) (exempt bool) {
	if cfg.Smart.Disabled {
		return false
	}
	if periodic {
		// Already flagged: exemption holds while the threshold cap admits it.
		return thresholdDays < cfg.Smart.MaxThresholdDays
	}
	if !exemptionActive(cfg, thresholdDays) {
		return false
	}
	events, err := s.queries.ListDeviceArchiveEvents(ctx, id)
	if err != nil {
		s.logger.Warn("archive: pattern event load failed", "device_id", id, "error", err)
		return false
	}
	cycle, ok := recognize(cfg, appearance(events), now)
	if !ok {
		return false
	}
	if err := s.setPeriodic(ctx, id, cycle, now); err != nil {
		s.logger.Warn("archive: pattern set failed", "device_id", id, "error", err)
		return false
	}
	return true
}

func (s *Service) setPeriodic(ctx context.Context, id int64, cycleDays float64, now time.Time) error {
	if _, err := s.queries.SetDevicePeriodic(ctx, db.SetDevicePeriodicParams{
		Periodic: 1, PeriodicCycleDays: cycleDays, UpdatedAt: now, ID: id,
	}); err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]any{"cycle_days": cycleDays})
	return s.insertEvent(ctx, id, EventPatternLearned, TriggerPattern, string(detail), now)
}

func (s *Service) clearPattern(ctx context.Context, id int64, now time.Time, reason string) error {
	if _, err := s.queries.SetDevicePeriodic(ctx, db.SetDevicePeriodicParams{
		Periodic: 0, PeriodicCycleDays: 0, UpdatedAt: now, ID: id,
	}); err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]any{"reason": reason})
	return s.insertEvent(ctx, id, EventPatternCleared, TriggerPattern, string(detail), now)
}
