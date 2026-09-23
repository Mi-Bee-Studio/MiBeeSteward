// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"mibee-steward/internal/db"
)

// Settings-center overlay keys (dotted names, one system_settings row each;
// value = JSON of the corresponding config struct).
const (
	SettingAuthPasswordPolicy = "auth.password_policy"
	SettingAuthLockout        = "auth.lockout"
)

// SettingsService is the runtime-editable settings overlay: system_settings
// rows that override the startup YAML (which itself overrides compiled
// defaults). The whole table is loaded into memory at construction; reads are
// an RWMutex-guarded map hit, writes persist to the DB and swap the in-memory
// value before notifying subscribers. Consumers resolve effective values
// (overlay ?? config) themselves via Get, the service knows
// nothing about config structs beyond round-tripping JSON.
//
// This is the settings-center half of "configuration without SSH": auth
// policy/lockout ride it today; engine-level knobs (discovery sources,
// scanner tuning, retention) subscribe via SetSubscriber when they gain
// hot-reload, following the notification-engine/probe-target pattern of
// "read fresh at the point of use, no restart".
type SettingsService struct {
	queries *db.Queries

	mu     sync.RWMutex
	values map[string]json.RawMessage
	subs   map[string][]func(json.RawMessage)
}

// NewSettingsService loads the overlay table into memory. A load failure is
// fatal-ish for the constructor contract (the center cannot run with an
// unreadable settings table), so callers get the error.
func NewSettingsService(dbConn db.DBTX) (*SettingsService, error) {
	s := &SettingsService{
		queries: db.New(dbConn),
		values:  make(map[string]json.RawMessage),
		subs:    make(map[string][]func(json.RawMessage)),
	}
	rows, err := s.queries.ListSettings(context.Background())
	if err != nil {
		return nil, fmt.Errorf("settings overlay load: %w", err)
	}
	for _, row := range rows {
		s.values[row.Key] = json.RawMessage(row.Value)
	}
	return s, nil
}

// Get decodes the overlay value for key into dst. Returns false when the key
// has no overlay row (caller falls back to the config/defaults layer).
func (s *SettingsService) Get(key string, dst any) bool {
	s.mu.RLock()
	raw, ok := s.values[key]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		// A malformed overlay row must not brick reads, log and treat as
		// unset (the config layer takes over); the admin can overwrite it.
		slog.Warn("settings overlay: malformed JSON, ignoring", "key", key, "error", err)
		return false
	}
	return true
}

// Has reports whether key has an overlay row (used by the settings UI to
// show "managed in web UI" vs "from config file").
func (s *SettingsService) Has(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.values[key]
	return ok
}

// Set validates by round-trip, persists to system_settings, swaps the
// in-memory value, then notifies subscribers with the raw JSON. In-memory
// swap happens only after the DB write succeeds (crash-safe: memory never
// leads the durable layer).
func (s *SettingsService) Set(ctx context.Context, key string, val any) error {
	raw, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("settings overlay marshal %s: %w", key, err)
	}
	if err := s.queries.UpsertSetting(ctx, db.UpsertSettingParams{
		Key:   key,
		Value: string(raw),
	}); err != nil {
		return fmt.Errorf("settings overlay persist %s: %w", key, err)
	}

	s.mu.Lock()
	s.values[key] = raw
	var subs []func(json.RawMessage)
	subs = append(subs, s.subs[key]...)
	s.mu.Unlock()

	for _, fn := range subs {
		fn(raw)
	}
	return nil
}

// SetSubscriber registers fn for change notifications on key. Subscribers run
// synchronously on the Set caller's goroutine after the DB write + memory
// swap, keep them cheap (swap a struct pointer, poke a channel), never call
// back into Set (deadlock via the write lock is the failure mode).
func (s *SettingsService) SetSubscriber(key string, fn func(raw json.RawMessage)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subs[key] = append(s.subs[key], fn)
}
