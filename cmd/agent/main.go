// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Command mibee-agent is the lightweight discovery agent for distributed MiBee
// Steward. It runs the scannerv2 engine locally (against the network it sits
// on) and reports results to an aggregation center via POST /agents/report. It
// is the agent half of the "agent + discovery + watch" form factor: no API, no
// SPA, no users — just scan + report. See docs/private/architecture-future.md.
//
// Mode is selected by config: when `center.url` is set the binary runs as an
// agent; otherwise it would be a center (use cmd/server for that). This binary
// always runs in agent mode and requires center.url + center.auth_token +
// network.name.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"mibee-steward/internal/agent"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	scannerv2discovery "mibee-steward/internal/service/scannerv2/discovery"
	scannerv2ebpf "mibee-steward/internal/service/scannerv2/ebpf"
	scannerv2engine "mibee-steward/internal/service/scannerv2/engine"
	scannerv2probe "mibee-steward/internal/service/scannerv2/probe"
	scannerv2runner "mibee-steward/internal/service/scannerv2/runner"
	scannerv2scheduler "mibee-steward/internal/service/scannerv2/scheduler"
	"mibee-steward/internal/version"
)

var (
	configPath  = flag.String("config", "configs/agent.yaml", "Path to agent config file")
	showVersion = flag.Bool("version", false, "Print the build version and exit")
)

func main() {
	flag.Parse()
	if *showVersion {
		fmt.Println("mibee-agent", version.Version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	if cfg.Center.URL == "" {
		fmt.Fprintln(os.Stderr, "center.url is required (this binary runs in agent mode; use cmd/server for the center)")
		os.Exit(1)
	}
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid config: %v\n", err)
		os.Exit(1)
	}
	initLogger(cfg.Log)
	slog.Info("starting mibee-agent",
		"version", version.Version,
		"center", cfg.Center.URL, "network", cfg.Network.Name, "agent_id_label", cfg.Network.Name)

	// Local mini-DB: the scheduler reads scan_tasks and the runner writes
	// scan_task_runs/scan_results + the device bridge writes devices. The agent
	// keeps these as a LOCAL shadow (its own recent view + run history); the
	// authoritative asset registry lives on the center. A tiny schema with just
	// the tables the runner/scheduler touch keeps the agent self-contained.
	dbPath := filepath.Join(filepath.Dir(*configPath), "agent.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		slog.Error("failed to create data directory", "error", err, "path", filepath.Dir(dbPath))
		os.Exit(1)
	}
	dbConn, err := openAgentDB(dbPath)
	if err != nil {
		slog.Error("failed to open agent db", "error", err)
		os.Exit(1)
	}
	defer dbConn.Close()
	queries := db.New(dbConn)

	// Engine: same construction as the center (routes.go), minus center-only
	// concerns. dbConn lets the engine's store write the local shadow devices.
	scannerPortSpec := cfg.Scanner.PipelineDefaults.DefaultPorts
	if scannerPortSpec == "" {
		scannerPortSpec = config.DefaultScanPortSpec
	}
	engine, engineErr := scannerv2engine.NewEngine(dbConn, scannerv2engine.Config{
		PortSpec:           scannerPortSpec,
		MaxConcurrentHosts: cfg.Scanner.MaxConcurrentHosts,
		MaxConcurrentScans: cfg.Scanner.MaxConcurrentScans,
		PerHostTimeout:     time.Duration(cfg.Scanner.DefaultTimeout) * time.Second,
		PerProbeTimeout:    time.Duration(cfg.Scanner.PerProbeTimeout) * time.Second,
		PersistRawEvidence: cfg.Scanner.PersistRawEvidence,
		OUIPath:            cfg.Scanner.OUIPath,
		FingerprintPath:    cfg.Scanner.FingerprintPath,
		SNMPCommunity:      cfg.Scanner.SNMPCommunity,
		RouterARP: scannerv2probe.RouterARPConfig{
			Routers:   cfg.Scanner.RouterARP.Routers,
			Community: cfg.Scanner.SNMPCommunity,
			Timeout:   time.Duration(cfg.Scanner.DefaultTimeout) * time.Second,
		},
		HeartbeatInterval: cfg.Heartbeat.DefaultInterval,
		HeartbeatTimeout:  cfg.Heartbeat.Timeout,
		EBPF: scannerv2ebpf.Config{
			Enabled:    cfg.Scanner.EBPF.Enabled,
			Interfaces: cfg.Scanner.EBPF.Interfaces,
		},
	}, slog.Default())
	if engineErr != nil {
		slog.Error("failed to init scannerv2 engine", "error", engineErr)
	}

	// Reporter: receives alive HostReports from the runner and POSTs them to the
	// center. The agent's network identity is encoded in its token (resolved on
	// the center); the reporter just ships the discovery payload.
	flush := parseDurationOrDefault(cfg.Center.ReportInterval, 30*time.Second)
	reporter := agent.NewReporter(cfg.Center.URL, cfg.Center.AuthToken, cfg.Network.Name, cfg.Network.CIDR, flush, 256, slog.Default())
	ctxBg, cancel := context.WithCancel(context.Background())
	defer cancel()
	reporter.Start(ctxBg)

	// Runner: reused from the center. reportSink forwards scans upstream.
	// networkID=0 here — the agent's LOCAL shadow devices get NULL network_id;
	// the center tags its copies with the agent's network from the token.
	scanRunner := scannerv2runner.New(engine, queries, dbConn, nil, 0, slog.Default())
	scanRunner.SetRepo(engine.Repository) // device-identity upsert for the agent's LOCAL shadow devices
	scanRunner.SetReportSink(reporter.Report)
	scanRunner.SetLostThreshold(cfg.Scanner.LostThreshold) // scanner.lost_threshold (default 2; <=0 keeps default)

	// Scheduler: cron-driven local scans. The agent's scan_tasks live in its own
	// mini-DB (seeded manually or via the task API on the center in a later
	// phase). For now an operator adds rows to scan_tasks directly.
	scanScheduler, schedErr := scannerv2scheduler.New(queries, dbConn,
		func(ctx context.Context, taskID int64, targets string, timeout time.Duration, concurrentHosts int, credentialID int64) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("scan_func_panic", "task_id", taskID, "panic", r)
				}
			}()
			// Agent-side v3 credential support is intentionally deferred (TODO
			// issue #135): it requires the agent to hold its own credential DB
			// + master key, which is a larger distributed-credentials design.
			// For now the agent ignores credential_id and uses its global v1/v2c
			// community. Passing 0 here preserves the existing behavior.
			_ = credentialID
			scanRunner.Run(ctx, taskID, targets, timeout, concurrentHosts, cfg.Scanner.PersistRawEvidence, 0)
		}, slog.Default())
	if schedErr != nil {
		slog.Error("failed to create scan scheduler", "error", schedErr)
	}
	if scanScheduler != nil {
		scanScheduler.Start(ctxBg)
		slog.Info("agent scan scheduler started")
	}

	// Passive discovery service — the SAME wiring the center uses
	// (internal/api/routes/routes.go), so the agent gets the passive ARP-cache +
	// multicast + router_arp sources for free. This is Phase A of the
	// router-agent roadmap: a router-resident agent (or a center deployed on a
	// router, form C) sees a far richer broadcast domain than a random LAN host,
	// and the existing discovery/ sources capture that choke-point value without
	// new code. The discovery config block (scanner.discovery.*) is shared with
	// the center; an operator enables the same sources in agent.yaml.
	//
	// The sources write through the runner's device bridge → reportSink →
	// upstream reporter, so passively-discovered hosts reach the center via the
	// same path as actively-scanned ones. discCancel is invoked on shutdown.
	var discCancel context.CancelFunc
	if cfg.Scanner.Discovery.Enabled {
		discSvc := scannerv2discovery.New(
			scannerv2discovery.Config{
				Interval:        time.Duration(cfg.Scanner.Discovery.Interval) * time.Second,
				TriggerIdentify: cfg.Scanner.Discovery.TriggerIdentify,
			},
			scannerv2discovery.SinkAdapter{Runner: scanRunner},
			scannerv2discovery.IdentifierAdapter(engine),
			dbConn, 0, slog.Default(),
		)
		discCtx, cancel := context.WithCancel(ctxBg)
		discCancel = cancel
		discSvc.Start(discCtx)
		interval := time.Duration(cfg.Scanner.Discovery.Interval) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}
		var activeSources []string
		// router_arp: widest coverage — one SNMP Walk per configured router.
		if cfg.Scanner.Discovery.RouterARP.Enabled {
			routerCommunity := cfg.Scanner.SNMPCommunity
			if cfg.Scanner.RouterARP.Community != "" {
				routerCommunity = cfg.Scanner.RouterARP.Community
			}
			routerTimeout := time.Duration(cfg.Scanner.PerProbeTimeout) * time.Second
			if routerTimeout <= 0 {
				routerTimeout = 3 * time.Second
			}
			routerARPSrc := scannerv2discovery.NewRouterARPSource(
				cfg.Scanner.RouterARP.Routers, routerCommunity, routerTimeout,
				interval, discSvc, slog.Default(),
			)
			routerARPSrc.Start(discCtx)
			activeSources = append(activeSources, "router_arp")
		}
		// arp_cache: free byproduct of normal operation (reads /proc/net/arp).
		if cfg.Scanner.Discovery.ARPCache.Enabled {
			arpCacheSrc := scannerv2discovery.NewARPCacheSource(interval, discSvc, slog.Default())
			arpCacheSrc.Start(discCtx)
			activeSources = append(activeSources, "arp_cache")
		}
		// multicast: passive mDNS/SSDP listener (zero outbound traffic).
		if cfg.Scanner.Discovery.Multicast.Enabled {
			mcastSrc := scannerv2discovery.NewMulticastSource(discSvc, slog.Default())
			mcastSrc.Start(discCtx)
			activeSources = append(activeSources, "multicast")
		}
		// dhcp_leases: Tier-1 router signal — the DHCP authority's hostname↔MAC↔IP
		// map. No-op on a host that isn't the LAN's DHCP server (file absent).
		if cfg.Scanner.Discovery.DHCPLeases.Enabled {
			dhcpSrc := scannerv2discovery.NewDHCPLeasesSource(interval, "", discSvc, slog.Default())
			dhcpSrc.Start(discCtx)
			activeSources = append(activeSources, "dhcp_leases")
		}
		// conntrack: Tier-1 router signal — the NAT choke point's "who is talking
		// RIGHT NOW" view. Filters to the agent's own LAN CIDR.
		if cfg.Scanner.Discovery.Conntrack.Enabled {
			conntrackSrc := scannerv2discovery.NewConntrackSource(cfg.Network.CIDR, interval, discSvc, slog.Default())
			conntrackSrc.Start(discCtx)
			activeSources = append(activeSources, "conntrack")
		}
		// hostapd: Tier-1 router/AP signal — WiFi STA associations (signal dBm,
		// connect time, SSID). hostapd ctrl socket first, iw station dump fallback.
		if cfg.Scanner.Discovery.Hostapd.Enabled {
			hostapdSrc := scannerv2discovery.NewHostapdSource(cfg.Scanner.Discovery.Hostapd.Interfaces, interval, discSvc, slog.Default())
			hostapdSrc.Start(discCtx)
			activeSources = append(activeSources, "hostapd")
		}
		// dns_log: Tier-1 router signal — tails the dnsmasq query log for passive
		// DNS fingerprinting (devices that block inbound probes still do DNS).
		if cfg.Scanner.Discovery.DNSLog.Enabled {
			dnsLogSrc := scannerv2discovery.NewDNSLogSource(interval, cfg.Scanner.Discovery.DNSLog.Path, discSvc, slog.Default())
			dnsLogSrc.Start(discCtx)
			activeSources = append(activeSources, "dns_log")
		}
		// arp_scan: WITH_ARPSCAN build only; NewARPScanSource returns nil
		// otherwise (or without CAP_NET_RAW) — nil guard skips it silently.
		if cfg.Scanner.Discovery.ARPScan.Enabled {
			if arpScanSrc := scannerv2discovery.NewARPScanSource(
				cfg.Network.CIDR, interval, cfg.Scanner.ARPScan.Interface,
				discSvc, slog.Default(),
			); arpScanSrc != nil {
				arpScanSrc.Start(discCtx)
				activeSources = append(activeSources, "arp_scan")
			}
		}
		// lldp_frame / cdp_frame: WITH_LLDP / WITH_CDP builds only; the New*
		// constructors return nil in the default build → skipped silently.
		if lldpSrc := scannerv2discovery.NewLLDPFrameSource(
			cfg.Scanner.Discovery.LLDPInterfaces, discSvc, nil, slog.Default(),
		); lldpSrc != nil {
			lldpSrc.Start(discCtx)
			activeSources = append(activeSources, "lldp_frame")
		}
		if cdpSrc := scannerv2discovery.NewCDPFrameSource(
			cfg.Scanner.Discovery.LLDPInterfaces, discSvc, nil, slog.Default(),
		); cdpSrc != nil {
			cdpSrc.Start(discCtx)
			activeSources = append(activeSources, "cdp_frame")
		}

		discSvc.SetSources(activeSources)
		slog.Info("agent passive discovery ready",
			"interval", interval.String(),
			"sources", activeSources,
			"trigger_identify", cfg.Scanner.Discovery.TriggerIdentify)
	}

	// Command poller: fetches ad-hoc scan commands from the center (Phase 5c).
	// The runScan callback wraps the runner so this package doesn't import runner
	// directly (avoids an import cycle). Commands are best-effort — the agent's
	// own cron scheduler is the primary scan driver.
	cmdPoller := agent.NewCommandPoller(cfg.Center.URL, cfg.Center.AuthToken, 60*time.Second, cfg.Network.CIDR,
		func(ctx context.Context, targets string, timeoutSec int) (string, error) {
			if scanRunner == nil {
				return "", fmt.Errorf("scan engine not initialized")
			}
			to := time.Duration(timeoutSec) * time.Second
			if to <= 0 {
				to = time.Duration(cfg.Scanner.DefaultTimeout) * time.Second
			}
			// Create a transient local task row so the run is recorded in the
			// agent's mini-DB (run history). taskID=0 → a throwaway row.
			run, err := queries.CreateScanTaskRun(ctx, db.CreateScanTaskRunParams{
				TaskID: 0, StartedAt: ptrTime(time.Now()),
			})
			if err != nil {
				return "", fmt.Errorf("create run: %w", err)
			}
			scanRunner.Run(ctx, run.ID, targets, to, cfg.Scanner.MaxConcurrentHosts, cfg.Scanner.PersistRawEvidence, 0)
			return fmt.Sprintf(`{"run_id":%d,"targets":"%s"}`, run.ID, targets), nil
		}, slog.Default())
	cmdPoller.Start(ctxBg)

	slog.Info("mibee-agent running", "center", cfg.Center.URL, "flush_interval", flush)

	// Wait for interrupt.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("shutting down mibee-agent...")
	cancel()
	if discCancel != nil {
		discCancel() // stop passive-discovery sources before the runner goes away
	}
	cmdPoller.Stop()
	if scanScheduler != nil {
		scanScheduler.Stop()
	}
	reporter.Stop() // final best-effort flush
	slog.Info("mibee-agent stopped")
}

func ptrTime(t time.Time) *time.Time { return &t }

// openAgentDB opens a local SQLite file with WAL + the mini schema the runner
// and scheduler need (scan_tasks, scan_task_runs, scan_results, devices + the
// networks/vlans FK targets + heartbeat_configs for the device bridge). It does
// NOT run the center's full migration suite — the agent owns only these tables.
func openAgentDB(dbPath string) (*sql.DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(8)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	if _, err := conn.Exec(agentSchema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("apply agent schema: %w", err)
	}
	return conn, nil
}

// agentSchema is the minimal table set the runner + scheduler touch. Shapes
// mirror db/schema.sql so the sqlc-generated queries compile against them.
const agentSchema = `
CREATE TABLE IF NOT EXISTS networks (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
	cidr TEXT, site TEXT, agent_id TEXT,
	metadata TEXT NOT NULL DEFAULT '{}',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vlans (
	id INTEGER PRIMARY KEY AUTOINCREMENT, vlan_tag INTEGER NOT NULL, name TEXT,
	description TEXT, network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
	first_seen DATETIME, last_seen DATETIME, UNIQUE(vlan_tag, network_id)
);
CREATE TABLE IF NOT EXISTS scan_tasks (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, targets TEXT NOT NULL,
	cron_expr TEXT NOT NULL DEFAULT '0 */6 * * *', pipeline_config TEXT NOT NULL DEFAULT '{}',
	global_labels TEXT NOT NULL DEFAULT '{}', timeout INTEGER NOT NULL DEFAULT 300,
	concurrent_hosts INTEGER NOT NULL DEFAULT 50, enabled INTEGER NOT NULL DEFAULT 1,
	last_run_at TIMESTAMP, next_run_at TIMESTAMP, last_run_status TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scan_task_runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
	status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled')),
	total_hosts INTEGER NOT NULL DEFAULT 0, alive_hosts INTEGER NOT NULL DEFAULT 0,
	new_hosts INTEGER NOT NULL DEFAULT 0, updated_hosts INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0, error_message TEXT NOT NULL DEFAULT '',
	started_at TIMESTAMP, finished_at TIMESTAMP,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_task ON scan_task_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_status ON scan_task_runs(status);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_created_at ON scan_task_runs(created_at);
CREATE TABLE IF NOT EXISTS scan_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE, run_id INTEGER,
	ip TEXT NOT NULL, alive INTEGER NOT NULL DEFAULT 0, rtt_ms INTEGER NOT NULL DEFAULT 0,
	ports TEXT NOT NULL DEFAULT '[]', services TEXT NOT NULL DEFAULT '{}', snmp_data TEXT NOT NULL DEFAULT '{}',
	prometheus_detected INTEGER NOT NULL DEFAULT 0, prometheus_url TEXT NOT NULL DEFAULT '',
	node_exporter_detected INTEGER NOT NULL DEFAULT 0, node_exporter_url TEXT NOT NULL DEFAULT '',
	node_exporter_data TEXT NOT NULL DEFAULT '{}', scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_results_task_ip ON scan_results(task_id, ip);
CREATE INDEX IF NOT EXISTS idx_scan_results_task ON scan_results(task_id);
CREATE TABLE IF NOT EXISTS heartbeat_configs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	device_id INTEGER NOT NULL, method TEXT NOT NULL CHECK(method IN ('icmp','http','tcp','snmp')),
	target TEXT NOT NULL, interval_seconds INTEGER NOT NULL DEFAULT 30,
	timeout_seconds INTEGER NOT NULL DEFAULT 5, snmp_community TEXT NOT NULL DEFAULT 'public',
	snmp_oid TEXT NOT NULL DEFAULT '1.3.6.1.2.1.1.3.0', enabled INTEGER NOT NULL DEFAULT 1, -- sysUpTimeInstance; keep in sync with config.SysUpTimeOID (raw-string DDL can't reference the const)
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_heartbeat_configs_device_method ON heartbeat_configs(device_id, method);
CREATE TABLE IF NOT EXISTS devices (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
	type TEXT NOT NULL DEFAULT 'other', brand TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
	location TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'unknown', ip_address TEXT NOT NULL DEFAULT '', mac_address TEXT NOT NULL DEFAULT '',
	serial_number TEXT NOT NULL DEFAULT '', purchase_date TEXT NOT NULL DEFAULT '', warranty_expiry TEXT NOT NULL DEFAULT '',
	tags TEXT NOT NULL DEFAULT '{}', scan_source TEXT NOT NULL DEFAULT 'manual', prometheus_labels TEXT NOT NULL DEFAULT '{}',
	last_scanned_at TIMESTAMP, last_scan_task_id INTEGER, open_ports TEXT NOT NULL DEFAULT '[]',
	detected_services TEXT NOT NULL DEFAULT '[]', prometheus_url TEXT NOT NULL DEFAULT '', node_exporter_url TEXT NOT NULL DEFAULT '',
	last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
	scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
	user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
	network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
	first_seen TIMESTAMP, last_seen TIMESTAMP,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_network ON devices(ip_address, network_id);
CREATE INDEX IF NOT EXISTS idx_devices_mac_address ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_scan_mac_expr ON devices(json_extract(scan_attributes, '$.mac'));
`

func initLogger(cfg config.LogConfig) {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var h slog.Handler
	if cfg.Format == "json" {
		h = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		h = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	slog.SetDefault(slog.New(h))
}

func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
