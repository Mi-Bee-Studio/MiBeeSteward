// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/config"
)

// setupSettingsService opens an in-memory DB with the system_settings table
// and loads the overlay.
func setupSettingsService(t *testing.T) (*SettingsService, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE system_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)

	svc, err := NewSettingsService(db)
	require.NoError(t, err)
	return svc, db
}

func TestSettingsService_SetGetRoundTrip(t *testing.T) {
	svc, _ := setupSettingsService(t)

	require.False(t, svc.Has(SettingAuthPasswordPolicy), "no overlay row before Set")

	policy := config.PasswordPolicyConfig{MinLength: 10, RequireDigit: true}
	require.NoError(t, svc.Set(context.Background(), SettingAuthPasswordPolicy, policy))

	require.True(t, svc.Has(SettingAuthPasswordPolicy))
	var got config.PasswordPolicyConfig
	require.True(t, svc.Get(SettingAuthPasswordPolicy, &got))
	require.Equal(t, policy, got)

	// Overwrite replaces the whole value (no per-key merge).
	require.NoError(t, svc.Set(context.Background(), SettingAuthPasswordPolicy, config.PasswordPolicyConfig{MinLength: 4}))
	var got2 config.PasswordPolicyConfig
	require.True(t, svc.Get(SettingAuthPasswordPolicy, &got2))
	require.Equal(t, config.PasswordPolicyConfig{MinLength: 4}, got2)
}

// The overlay wins over the UserService's startup policy, and applies at
// USE time, so an admin edit changes the next validation without any restart
// or reconstruction (the settings-center core property). The UserService and
// SettingsService may sit on different handles; the overlay is read through
// SettingsService only.
func TestSettingsService_PolicyOverlayPrecedenceAndHotUpdate(t *testing.T) {
	settingsSvc, _ := setupSettingsService(t)
	userSvc, _ := setupUserService(t)

	// Default policy: "Sh0rt" is too short (min 8).
	_, err := userSvc.Register(context.Background(), "carol", "carol@example.com", "Sh0rt", "user")
	require.ErrorIs(t, err, ErrWeakPassword)

	// Overlay relaxes min_length to 4, same service instance now accepts it.
	require.NoError(t, settingsSvc.Set(context.Background(), SettingAuthPasswordPolicy,
		config.PasswordPolicyConfig{MinLength: 4, RequireUppercase: true, RequireLowercase: true, RequireDigit: true}))
	userSvc.SetSettingsSource(settingsSvc)
	_, err = userSvc.Register(context.Background(), "carol", "carol@example.com", "Sh0rt", "user")
	require.NoError(t, err, "overlay must override the constructor policy at use time")

	// EffectivePasswordPolicy mirrors the overlay for the public endpoint.
	require.Equal(t, 4, userSvc.EffectivePasswordPolicy().MinLength)
}

func TestSettingsService_SubscriberNotified(t *testing.T) {
	svc, _ := setupSettingsService(t)

	var calls atomic.Int32
	svc.SetSubscriber(SettingAuthLockout, func(_ json.RawMessage) { calls.Add(1) })

	require.NoError(t, svc.Set(context.Background(), SettingAuthLockout, config.LockoutConfig{MaxFailedAttempts: 3, LockMinutes: 5}))
	require.Equal(t, int32(1), calls.Load(), "Set must notify the subscriber")

	// Other keys don't fire this subscriber.
	require.NoError(t, svc.Set(context.Background(), SettingAuthPasswordPolicy, config.PasswordPolicyConfig{MinLength: 6}))
	require.Equal(t, int32(1), calls.Load())
}

// A malformed overlay row must not brick reads, treated as unset, the config
// layer takes over.
func TestSettingsService_MalformedRowIgnored(t *testing.T) {
	svc, db := setupSettingsService(t)
	_, err := db.Exec(`INSERT INTO system_settings (key, value) VALUES ('auth.password_policy', 'not json')`)
	require.NoError(t, err)
	_ = svc

	// The row was inserted after load, simulate a restart-era read by
	// re-loading a second service over the same DB.
	svc2, err := NewSettingsService(db)
	require.NoError(t, err)

	var p config.PasswordPolicyConfig
	require.False(t, svc2.Get(SettingAuthPasswordPolicy, &p), "malformed overlay row must read as unset")
	require.True(t, svc2.Has(SettingAuthPasswordPolicy), "Has still reports the row exists (UI shows it as overlay-managed)")
}
