// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
)

// TestRunAgent_LifecycleAndCleanShutdown drives the REAL agent lifecycle
// in-process: mini-DB open + migrations, engine assembly, reporter, runner,
// scheduler, passive-discovery sources, vantage prober, command poller, and
// the remote-ops wiring, then cancels the context and asserts the graceful
// stop sequence returns nil. The center URL points at a dead loopback port:
// the reporter/poller are expected to fail-and-retry in the background, which
// is the agent's normal degraded mode and exactly what the lifecycle must
// survive.
func TestRunAgent_LifecycleAndCleanShutdown(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "agent.yaml")
	cfgYAML := `
center:
  url: "http://127.0.0.1:1"
  auth_token: "test-agent-token"
  report_interval: "30s"
  remote_ops_enabled: true
network:
  name: "agent-smoke"
  cidr: "192.0.2.0/24"
scanner:
  default_timeout: 5
  max_concurrent_hosts: 4
  discovery:
    enabled: true
    interval: 2
    trigger_identify: false
    arp_cache:
      enabled: true
    dhcp_leases:
      enabled: true
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o600))

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, validateForTest(cfg))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, cfg, cfgPath) }()

	// Let everything assemble and enter its steady state (first poller poll,
	// first discovery sweep tick, one reporter cycle).
	time.Sleep(2 * time.Second)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "graceful shutdown must be clean")
	case <-time.After(20 * time.Second):
		t.Fatal("runAgent did not return after ctx cancel")
	}

	// The mini-DB (schema + migrations applied) lives beside the config.
	require.FileExists(t, filepath.Join(tmp, "agent.db"))
}

// TestRunAgent_BadDBPath verifies the startup failure contract: a data
// directory that cannot be created shows up as a returned error, not a
// process exit.
func TestRunAgent_BadDBPath(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// A config path whose directory is a FILE → MkdirAll of its dir fails.
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	cfgPath := filepath.Join(blocker, "sub", "agent.yaml")

	cfg := &config.Config{}
	cfg.Center.URL = "http://127.0.0.1:1"
	cfg.Center.AuthToken = "t"
	cfg.Network.Name = "smoke"

	err := runAgent(context.Background(), cfg, cfgPath)
	require.Error(t, err)
}

// validateForTest mirrors main's config.Validate gate so the test fails at
// the assert (with the reason) instead of relying on the yaml being right.
func validateForTest(cfg *config.Config) error { return config.Validate(cfg) }
