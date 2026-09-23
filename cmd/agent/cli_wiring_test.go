// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

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

// quietAgentLogs swaps the default logger for a discarding one so startup
// banners don't flood test output.
func quietAgentLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// TestRunCLI_FrontDoors walks the argv front's validation ladder: -version
// short-circuits, a bad flag errors, a missing config errors, a config
// without center.url errors, and an invalid config errors.
func TestRunCLI_FrontDoors(t *testing.T) {
	quietAgentLogs(t)

	*showVersion = true
	*configPath = "unused.yaml"
	require.NoError(t, runCLI(nil))
	*showVersion = false

	require.Error(t, runCLI([]string{"-no-such-flag"}))

	*configPath = filepath.Join(t.TempDir(), "missing.yaml")
	err := runCLI(nil)
	require.ErrorContains(t, err, "failed to load config")

	// Valid YAML with the shared auth block, but no center.url → agent-mode
	// requirement (config.Load rejects a missing jwt_secret before this).
	noCenter := filepath.Join(t.TempDir(), "agent.yaml")
	require.NoError(t, os.WriteFile(noCenter, []byte("auth:\n  jwt_secret: \"test-secret-value-32-chars-long-ok!\"\nnetwork:\n  name: x\n"), 0o600))
	*configPath = noCenter
	err = runCLI(nil)
	require.ErrorContains(t, err, "center.url is required")
}

// TestRunAgent_AllSourcesWiring drives ONE full lifecycle with every passive
// source enabled, each source's wiring branch (constructor + Start +
// activeSources append) executes, and unbuildable listeners degrade with
// warnings instead of killing the agent.
func TestRunAgent_AllSourcesWiring(t *testing.T) {
	quietAgentLogs(t)
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "agent.yaml")
	cfgYAML := `
center:
  url: "http://127.0.0.1:1"
  auth_token: "test-agent-token"
  report_interval: "30s"
network:
  name: "agent-all-sources"
  cidr: "192.0.2.0/24"
scanner:
  default_timeout: 5
  max_concurrent_hosts: 4
  snmp_community: "public"
  router_arp:
    routers: ["192.0.2.1"]
    community: "router-comm"
  discovery:
    enabled: true
    interval: 2
    trigger_identify: false
    arp_cache:
      enabled: true
    dhcp_leases:
      enabled: true
    conntrack:
      enabled: true
    hostapd:
      enabled: true
      interfaces: ["wlan0"]
    dns_log:
      enabled: true
      path: "` + filepath.ToSlash(filepath.Join(tmp, "dns.log")) + `"
    multicast:
      enabled: true
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o600))

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, cfg, cfgPath) }()

	time.Sleep(2 * time.Second)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "all-sources agent must still shut down cleanly")
	case <-time.After(20 * time.Second):
		t.Fatal("runAgent did not return after ctx cancel")
	}
}
