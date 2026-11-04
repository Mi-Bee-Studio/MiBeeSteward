// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package archive runs the asset-archive lifecycle engine (#663).
//
// It REPLACES the old silent-device physical prune: a scanner-discovered
// device offline past the threshold moves to the archive (archived_at
// stamped, row + every FK-attached history preserved) instead of being
// deleted. Archived devices that come back online briefly (one or two short
// appearances) stay archived; only continuous online past the restore
// threshold returns the asset to the live library. Every transition appends
// one asset_archive_events row — the dossier timeline backbone and (for #664)
// the periodic-pattern learner's data source.
//
// Priority order (highest wins):
//
//	archive_pin force_archive / force_active  — manual pins, never overridden
//	manual archive / restore                  — one-time actions (this package)
//	automatic rules                           — thresholds below
//
// The engine runs its own fast ticker (default 60s) rather than riding the
// retention sweeper's 6h cadence: the continuous-online restore timer needs
// minute-scale resolution, and the archived set is small so each pass is a
// handful of indexed queries. A failed write is not fatal — the state machine
// is idempotent, so the next tick simply retries the same transition.
package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// Pin values for devices.archive_pin (mirrors the schema CHECK).
const (
	PinNone         = ""
	PinForceArchive = "force_archive"
	PinForceActive  = "force_active"
)

// Event / trigger values for asset_archive_events (mirror the schema CHECKs).
const (
	EventArchived        = "archived"
	EventRestored        = "restored"
	EventOnlineBlip      = "online_blip"
	EventPatternLearned  = "pattern_learned"
	EventPatternCleared  = "pattern_cleared"
	EventPinSet          = "pin_set"
	EventPinCleared      = "pin_cleared"
	TriggerAutoOffline   = "auto_offline"
	TriggerAutoRestore   = "auto_restore"
	TriggerPattern       = "pattern"
	TriggerManual        = "manual"
)

// SettingKeyEngine is the settings-center overlay key (#663 runtime knobs).
// The overlay value (when present) is JSON with the same field names as
// ArchiveConfig and wins over the YAML config; absent fields fall back.
const SettingKeyEngine = "archive.engine"

// SettingsGetter is the slice of SettingsService the engine needs (structural
// interface keeps this package free of the internal/service import).
type SettingsGetter interface {
	Get(key string, dst any) bool
}

// Errors returned by the manual operations (surfaced by the API in #666).
var (
	// ErrNotArchived: restore requested for a device that is not archived.
	ErrNotArchived = errors.New("device is not archived")
	// ErrAlreadyArchived: manual archive requested for a device already in
	// the archive (idempotent no-op is reported, not silently swallowed).
	ErrAlreadyArchived = errors.New("device is already archived")
	// ErrPinned: restore requested for a force_archive-pinned device without
	// the force flag (which clears the pin first).
	ErrPinned = errors.New("device is pinned force_archive; force is required to restore")
	// ErrInvalidPin: SetPin called with a value outside the pin set.
	ErrInvalidPin = errors.New("invalid archive_pin value")
)

// Service is the archive lifecycle engine.
type Service struct {
	queries  *db.Queries
	cfg      config.ArchiveConfig
	settings SettingsGetter // nil ⇒ YAML config only
	interval time.Duration
	logger   *slog.Logger
	cancel   context.CancelFunc
	done     chan struct{}
}

// New constructs the engine. Defaults for zero-valued fields are expected to
// have been filled by config.normalizeArchive; New defends anyway (same
// convention as cleanup.New).
func New(queries *db.Queries, cfg config.ArchiveConfig, logger *slog.Logger) *Service {
	if cfg.OfflineDays <= 0 {
		cfg.OfflineDays = 7
	}
	if cfg.RestoreOnlineMinutes <= 0 {
		cfg.RestoreOnlineMinutes = 60
	}
	if cfg.SweepIntervalSeconds <= 0 {
		cfg.SweepIntervalSeconds = 60
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		queries:  queries,
		cfg:      cfg,
		interval: time.Duration(cfg.SweepIntervalSeconds) * time.Second,
		logger:   logger,
		done:     make(chan struct{}),
	}
}

// SetSettingsSource wires the settings-center overlay (nil-safe, chainable).
// When set, every tick re-reads SettingKeyEngine so runtime edits take effect
// without a restart (ADR-035 pattern).
func (s *Service) SetSettingsSource(g SettingsGetter) *Service {
	s.settings = g
	return s
}

// Start runs one pass immediately, then on every tick, until Stop.
func (s *Service) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	go func() {
		defer close(s.done)
		s.logger.Info("archive engine starting",
			"interval", s.interval,
			"offline_days", s.cfg.OfflineDays,
			"restore_online_minutes", s.cfg.RestoreOnlineMinutes)
		s.runOnce(ctx)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runOnce(ctx)
			}
		}
	}()
}

// Stop signals the loop to exit and waits for it (no-op before Start).
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}

// effectiveCfg merges the settings-center overlay over the YAML config. Fields
// left at zero in the overlay fall back to the constructor values.
func (s *Service) effectiveCfg() config.ArchiveConfig {
	cfg := s.cfg
	if s.settings == nil {
		return cfg
	}
	var overlay config.ArchiveConfig
	if !s.settings.Get(SettingKeyEngine, &overlay) {
		return cfg
	}
	if overlay.OfflineDays > 0 {
		cfg.OfflineDays = overlay.OfflineDays
	}
	if overlay.RestoreOnlineMinutes > 0 {
		cfg.RestoreOnlineMinutes = overlay.RestoreOnlineMinutes
	}
	return cfg
}

func (s *Service) runOnce(ctx context.Context) {
	cfg := s.effectiveCfg()
	s.autoArchive(ctx, cfg)
	s.stampOnline(ctx)
	s.restoreCheck(ctx, cfg)
	s.blipCheck(ctx)
}

// autoArchive moves offline scanner devices past their threshold into the
// archive. Manual devices (scan_source != 'scanner_v2') are excluded by the
// query — they respond to manual archive only. Per-device override wins over
// the global threshold (0/NULL = follow global). Time comparison happens in
// Go: offline_since TEXT is written with mixed serialization shapes.
func (s *Service) autoArchive(ctx context.Context, cfg config.ArchiveConfig) {
	candidates, err := s.queries.ListAutoArchiveCandidates(ctx)
	if err != nil {
		s.logger.Warn("archive: candidate select failed", "error", err)
		return
	}
	now := time.Now()
	var archived int
	for _, c := range candidates {
		if ctx.Err() != nil {
			return
		}
		thresholdDays := cfg.OfflineDays
		if c.OfflineDaysOverride > 0 {
			thresholdDays = int(c.OfflineDaysOverride)
		}
		if c.OfflineSince == nil || c.OfflineSince.After(now.AddDate(0, 0, -thresholdDays)) {
			continue
		}
		detail, _ := json.Marshal(map[string]any{
			"offline_days": thresholdDays,
			"has_mac":      c.MacAddress != "",
		})
		if _, err := s.queries.ArchiveDevice(ctx, db.ArchiveDeviceParams{
			ArchivedAt: &now, UpdatedAt: now, ID: c.ID,
		}); err != nil {
			s.logger.Warn("archive: archive write failed",
				"device_id", c.ID, "ip", c.IpAddress, "error", err)
			continue
		}
		if err := s.insertEvent(ctx, c.ID, EventArchived, TriggerAutoOffline, string(detail), now); err != nil {
			s.logger.Warn("archive: event write failed", "device_id", c.ID, "error", err)
		}
		archived++
	}
	if archived > 0 {
		s.logger.Info("archive: auto-archived offline devices",
			"count", archived, "offline_days", cfg.OfflineDays)
	}
}

// stampOnline starts the continuous-online clock for archived devices the
// moment they are observed online (status flips come from the existing scan
// bridge / heartbeat paths, which do not know about the archive).
func (s *Service) stampOnline(ctx context.Context) {
	now := time.Now()
	n, err := s.queries.StampArchivedOnlineSince(ctx, db.StampArchivedOnlineSinceParams{
		OnlineSince: &now, UpdatedAt: now,
	})
	if err != nil {
		s.logger.Warn("archive: online stamp failed", "error", err)
		return
	}
	if n > 0 {
		s.logger.Info("archive: archived device observed online, restore timer started", "count", n)
	}
}

// restoreCheck returns archived devices to the live library once they have
// been CONTINUOUSLY online past the threshold. force_archive-pinned devices
// are skipped (they keep the online_since stamp: "online but force-archived"
// stays visible, but they never leave the archive automatically).
func (s *Service) restoreCheck(ctx context.Context, cfg config.ArchiveConfig) {
	rows, err := s.queries.ListArchivedOnline(ctx)
	if err != nil {
		s.logger.Warn("archive: restore select failed", "error", err)
		return
	}
	now := time.Now()
	cutoff := now.Add(-time.Duration(cfg.RestoreOnlineMinutes) * time.Minute)
	var restored int
	for _, r := range rows {
		if ctx.Err() != nil {
			return
		}
		if r.ArchivePin == PinForceArchive {
			continue
		}
		if r.OnlineSince == nil || r.OnlineSince.After(cutoff) {
			continue
		}
		minutes := int(now.Sub(*r.OnlineSince).Minutes())
		if _, err := s.queries.RestoreArchivedDevice(ctx, db.RestoreArchivedDeviceParams{
			UpdatedAt: now, ID: r.ID,
		}); err != nil {
			s.logger.Warn("archive: restore write failed", "device_id", r.ID, "error", err)
			continue
		}
		detail, _ := json.Marshal(map[string]any{"online_minutes": minutes})
		if err := s.insertEvent(ctx, r.ID, EventRestored, TriggerAutoRestore, string(detail), now); err != nil {
			s.logger.Warn("archive: event write failed", "device_id", r.ID, "error", err)
		}
		restored++
	}
	if restored > 0 {
		s.logger.Info("archive: auto-restored devices to the asset library",
			"count", restored, "restore_online_minutes", cfg.RestoreOnlineMinutes)
	}
}

// blipCheck closes the online clock for archived devices whose online episode
// ended before the restore threshold: a brief appearance records an
// online_blip event (the #664 pattern learner's signal) and the device stays
// archived. One or two short blips therefore never move a device out.
func (s *Service) blipCheck(ctx context.Context) {
	rows, err := s.queries.ListArchivedOnlineBroken(ctx)
	if err != nil {
		s.logger.Warn("archive: blip select failed", "error", err)
		return
	}
	now := time.Now()
	for _, r := range rows {
		if ctx.Err() != nil {
			return
		}
		minutes := 0
		if r.OnlineSince != nil {
			minutes = int(now.Sub(*r.OnlineSince).Minutes())
		}
		if _, err := s.queries.ClearOnlineSince(ctx, db.ClearOnlineSinceParams{
			UpdatedAt: now, ID: r.ID,
		}); err != nil {
			s.logger.Warn("archive: blip clear failed", "device_id", r.ID, "error", err)
			continue
		}
		detail, _ := json.Marshal(map[string]any{"online_minutes": minutes})
		if err := s.insertEvent(ctx, r.ID, EventOnlineBlip, TriggerAutoRestore, string(detail), now); err != nil {
			s.logger.Warn("archive: event write failed", "device_id", r.ID, "error", err)
		}
	}
}

// --- Manual operations (one-time actions; API surface lands in #666) ---

// ArchiveDeviceManually archives a device regardless of source or status (a
// manual asset answers manual archive; an online device may be archived too —
// use PinForceArchive when it must STAY archived, otherwise the auto-restore
// timer applies once its online stretch passes the threshold).
func (s *Service) ArchiveDeviceManually(ctx context.Context, id int64, reason string) error {
	now := time.Now()
	n, err := s.queries.ArchiveDevice(ctx, db.ArchiveDeviceParams{
		ArchivedAt: &now, UpdatedAt: now, ID: id,
	})
	if err != nil {
		return fmt.Errorf("archive device: %w", err)
	}
	if n == 0 {
		return ErrAlreadyArchived
	}
	detail, _ := json.Marshal(map[string]any{"reason": reason})
	return s.insertEvent(ctx, id, EventArchived, TriggerManual, string(detail), now)
}

// RestoreDeviceManually returns an archived device to the asset library. A
// force_archive pin blocks the restore unless force is set, in which case the
// pin is cleared first (pin_cleared event) so the device cannot come back as
// a zombie still-pinned row.
func (s *Service) RestoreDeviceManually(ctx context.Context, id int64, force bool) error {
	dev, err := s.queries.GetDevice(ctx, id)
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}
	if dev.ArchivedAt == nil {
		return ErrNotArchived
	}
	now := time.Now()
	if dev.ArchivePin == PinForceArchive {
		if !force {
			return ErrPinned
		}
		if err := s.setPin(ctx, dev.ID, PinNone, now); err != nil {
			return err
		}
	}
	if _, err := s.queries.RestoreArchivedDevice(ctx, db.RestoreArchivedDeviceParams{
		UpdatedAt: now, ID: id,
	}); err != nil {
		return fmt.Errorf("restore device: %w", err)
	}
	return s.insertEvent(ctx, id, EventRestored, TriggerManual, "{}", now)
}

// SetPin sets or clears the manual archive pin (highest priority in the state
// machine). pin must be one of PinNone / PinForceArchive / PinForceActive.
func (s *Service) SetPin(ctx context.Context, id int64, pin string) error {
	switch pin {
	case PinNone, PinForceArchive, PinForceActive:
	default:
		return ErrInvalidPin
	}
	return s.setPin(ctx, id, pin, time.Now())
}

func (s *Service) setPin(ctx context.Context, id int64, pin string, now time.Time) error {
	if _, err := s.queries.SetDeviceArchivePin(ctx, db.SetDeviceArchivePinParams{
		ArchivePin: pin, UpdatedAt: now, ID: id,
	}); err != nil {
		return fmt.Errorf("set archive pin: %w", err)
	}
	event := EventPinSet
	if pin == PinNone {
		event = EventPinCleared
	}
	detail, _ := json.Marshal(map[string]any{"pin": pin})
	return s.insertEvent(ctx, id, event, TriggerManual, string(detail), now)
}

func (s *Service) insertEvent(ctx context.Context, deviceID int64, event, triggeredBy, detail string, at time.Time) error {
	return s.queries.InsertArchiveEvent(ctx, db.InsertArchiveEventParams{
		DeviceID: deviceID, Event: event, TriggeredBy: triggeredBy, Detail: detail, OccurredAt: at,
	})
}

// EffectiveThreshold returns the auto-archive threshold in days for a device
// (per-device override > global). Exposed for the API (#666 display) and the
// pattern learner (#664).
func (s *Service) EffectiveThreshold(override int64) int {
	if override > 0 {
		return int(override)
	}
	return s.effectiveCfg().OfflineDays
}

// NormalizePin validates a pin value from an untrusted caller; empty is
// normalized to PinNone. Returns ErrInvalidPin for anything else.
func NormalizePin(v string) (string, error) {
	v = strings.TrimSpace(v)
	switch v {
	case PinNone, PinForceArchive, PinForceActive:
		return v, nil
	default:
		return "", ErrInvalidPin
	}
}
