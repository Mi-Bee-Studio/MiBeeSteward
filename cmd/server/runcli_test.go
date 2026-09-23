// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRunCLI_FrontDoors walks the argv front's validation ladder: -version
// short-circuits, a bad flag errors, a missing config errors, and an
// unwritable data directory errors past the config load.
func TestRunCLI_FrontDoors(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	*showVersion = true
	*configPath = "unused.yaml"
	require.NoError(t, runCLI(nil))
	*showVersion = false

	require.Error(t, runCLI([]string{"-no-such-flag"}))

	*configPath = filepath.Join(t.TempDir(), "missing.yaml")
	err := runCLI(nil)
	require.ErrorContains(t, err, "failed to load config")

	// Valid config whose data directory cannot be created (parent is a
	// regular file) fails at the MkdirAll bootstrap.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	cfg := writeCenterConfig(t, dir, "")
	src, err := os.ReadFile(cfg)
	require.NoError(t, err)
	patched := strings.Replace(string(src),
		filepath.ToSlash(filepath.Join(dir, "data", "mibee.db")),
		filepath.ToSlash(blocker)+"/mibee.db", 1)
	require.NotEqual(t, string(src), patched, "db path must appear in the template")
	patchedCfg := filepath.Join(dir, "blocked.yaml")
	require.NoError(t, os.WriteFile(patchedCfg, []byte(patched), 0o600))
	*configPath = patchedCfg
	err = runCLI(nil)
	require.ErrorContains(t, err, "failed to create data directory")
}
