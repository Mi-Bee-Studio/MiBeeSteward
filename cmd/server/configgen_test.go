// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBeeSteward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
)

// TestEnsureConfigFile_GeneratesMissingConfig drives the #682 first-run path:
// a missing config file is generated minimal-but-valid — random jwt_secret,
// empty admin password (browser first-run), strict file permissions — and the
// result must actually load through the real config pipeline.
func TestEnsureConfigFile_GeneratesMissingConfig(t *testing.T) {
	dir := t.TempDir()
	// Nested path: parent directories must be created.
	path := filepath.Join(dir, "sub", "dir", "config.yaml")

	generated, err := ensureConfigFile(path)
	require.NoError(t, err)
	require.True(t, generated)

	// Second call: the file now exists → no-op.
	generated, err = ensureConfigFile(path)
	require.NoError(t, err)
	require.False(t, generated)

	// Permissions: the file carries the jwt_secret.
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// The generated config loads and validates as-is: valid jwt_secret
	// (≥32 chars, not the placeholder), empty admin password = browser
	// first-run path, listen defaults applied.
	cfg, err := config.Load(path)
	require.NoError(t, err, "generated config must pass full validation")
	require.GreaterOrEqual(t, len(cfg.Auth.JWTSecret), 32)
	require.NotEqual(t, "change-me-in-production", cfg.Auth.JWTSecret)
	require.Empty(t, cfg.Auth.InitialAdminPassword)
	require.Equal(t, 8080, cfg.Server.Port)
}

// TestEnsureConfigFile_NeverTouchesExistingConfig pins the safety invariant:
// an existing file — even a broken one — is never rewritten.
func TestEnsureConfigFile_NeverTouchesExistingConfig(t *testing.T) {
	dir := t.TempDir()

	// Valid existing file: content byte-identical after the call.
	path := filepath.Join(dir, "config.yaml")
	original := "server:\n  port: 9999\nauth:\n  jwt_secret: \"existing-secret-that-is-long-enough-32ch!\"\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0o600))
	generated, err := ensureConfigFile(path)
	require.NoError(t, err)
	require.False(t, generated)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(after))

	// Broken existing file: still untouched; the failure belongs to
	// config.Load, not to the generator.
	broken := filepath.Join(dir, "broken.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("\tnot: [yaml"), 0o600))
	generated, err = ensureConfigFile(broken)
	require.NoError(t, err)
	require.False(t, generated)
	after, err = os.ReadFile(broken)
	require.NoError(t, err)
	require.Equal(t, "\tnot: [yaml", string(after))
}

// TestRunCLI_ExistingBrokenConfigStillFails pins the end-to-end guarantee:
// runCLI surfaces the config error for an existing broken file (no silent
// regeneration) — the generation path only fires for a MISSING file.
func TestRunCLI_ExistingBrokenConfigStillFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("jwt_secret: [broken"), 0o600))

	err := runCLI([]string{"-config", path})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load config")
	// ... and the broken file was not silently replaced.
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "jwt_secret: [broken", string(after))
}

// TestMinimalConfigTemplateInvariants keeps the generated YAML honest: the
// security-relevant keys the template must NOT set (reserved-target escape
// hatch, master key seeding) stay absent.
func TestMinimalConfigTemplateInvariants(t *testing.T) {
	require.NotContains(t, minimalConfigTemplate, "allow_reserved_targets")
	require.NotContains(t, minimalConfigTemplate, "master_key")
	require.True(t, strings.Contains(minimalConfigTemplate, `initial_admin_password: ""`))
}
