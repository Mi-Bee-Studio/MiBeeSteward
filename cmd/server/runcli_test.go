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
// short-circuits, a bad flag errors, an ungeneratable config errors (a
// MISSING config is auto-generated since #682 — its happy path is covered by
// TestEnsureConfigFile_GeneratesMissingConfig, and letting runCLI proceed
// here would block in serve), and an unwritable data directory errors past
// the config load.
func TestRunCLI_FrontDoors(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	*showVersion = true
	*configPath = "unused.yaml"
	require.NoError(t, runCLI(nil))
	*showVersion = false

	require.Error(t, runCLI([]string{"-no-such-flag"}))

	// Missing config under a read-only parent: the #682 generation itself
	// fails and surfaces as an error — this is the runCLI wiring of the
	// generator, without booting the generated config into serve.
	roDir := t.TempDir()
	readonly := filepath.Join(roDir, "readonly")
	require.NoError(t, os.Mkdir(readonly, 0o500))
	*configPath = filepath.Join(readonly, "missing.yaml")
	err := runCLI(nil)
	require.ErrorContains(t, err, "generating a minimal one failed")
	// And nothing was created at the path.
	_, statErr := os.Stat(*configPath)
	require.True(t, os.IsNotExist(statErr), "no config may be created under a read-only parent")

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
