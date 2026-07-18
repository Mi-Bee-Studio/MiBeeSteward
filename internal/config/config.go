// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config is the root configuration struct.
type Config struct {
	Server     ServerConfig     `koanf:"server"`
	Database   DatabaseConfig   `koanf:"database"`
	Auth       AuthConfig       `koanf:"auth"`
	Heartbeat  HeartbeatConfig  `koanf:"heartbeat"`
	Prometheus PrometheusConfig `koanf:"prometheus"`
	Dashboard  DashboardConfig  `koanf:"dashboard"`
	Storage    StorageConfig    `koanf:"storage"`
	Log        LogConfig        `koanf:"log"`
	CORS       CORSConfig       `koanf:"cors"`
	RateLimit  RateLimitConfig  `koanf:"rate_limit"`
	SMTP       SMTPConfig       `koanf:"smtp"`
	Scanner    ScannerConfig    `koanf:"scanner"`
	// Retention governs the periodic background sweep that prunes high-volume
	// detail tables (heartbeat_results, scan_results, …). Without it these
	// tables grow unbounded — heartbeat_results alone accumulates ~270k rows/day.
	Retention RetentionConfig `koanf:"retention"`
	// Network identifies the logical network this instance is responsible for.
	// Used to resolve devices.network_id (seeded into the networks table at
	// startup). Single-instance default name is "default"; in a distributed
	// deployment each agent sets a distinct name (e.g. "lan-63", "branch-bj").
	Network NetworkConfig `koanf:"network"`
	// Center configures a discovery AGENT's upstream aggregation center. When
	// URL is non-empty the binary runs in agent mode: it runs the scannerv2
	// engine locally and reports results to this center via POST /agents/report
	// (auth: AuthToken, a long-lived agent token minted on the center). Empty
	// URL = center/standalone mode (serve API + SPA, no upstream reporting).
	Center CenterConfig `koanf:"center"`
}

// CenterConfig configures an agent's upstream center.
type CenterConfig struct {
	// URL is the center's base URL (e.g. "http://192.168.63.101:8080"). Empty =
	// standalone/center mode (no upstream reporting).
	URL string `koanf:"url"`
	// AuthToken is the agent's bearer token (minted on the center via
	// POST /api/v1/agents/tokens). Presented on every report.
	AuthToken string `koanf:"auth_token"`
	// ReportInterval is how often to flush buffered scan results upstream when
	// the buffer isn't full. Default 30s. Errors retry with exponential backoff.
	ReportInterval string `koanf:"report_interval"`
}

// NetworkConfig describes the logical network this instance scans/owns.
type NetworkConfig struct {
	// Name is the human-readable network identifier (resolved to a networks.id
	// at startup). Empty is treated as "default" at resolve time.
	Name string `koanf:"name"`
	// CIDR is the advisory network range (e.g. "192.168.63.0/24"). Not enforced;
	// recorded on the networks row for display and future subnet inference.
	CIDR string `koanf:"cidr"`
	// Site is an optional site label (branch / datacenter / cloud).
	Site string `koanf:"site"`
}

// RetentionConfig holds per-table retention windows and sweep tuning. A field
// of 0 means "use the documented default" (applied in Normalize), NOT "keep
// forever" — keeping forever is never the intent for these detail tables.
type RetentionConfig struct {
	// Per-table retention windows (days). Defaults reflect each table's mix of
	// troubleshooting value vs. volume: heartbeat is high-volume/low-value (7d),
	// audit is low-volume/high-value (90d).
	HeartbeatResultsDays int `koanf:"heartbeat_results_days"`
	ScanResultsDays      int `koanf:"scan_results_days"`
	ScanTaskRunsDays     int `koanf:"scan_task_runs_days"`
	AuditLogsDays        int `koanf:"audit_logs_days"`
	NotificationLogDays  int `koanf:"notification_log_days"`
	ServiceEvidenceDays  int `koanf:"service_evidence_days"`
	// ChangeLogDays is the retention window for change_log (device_added /
	// changed / lost events). Default 30 (high value for asset-history audits,
	// but change_log grows fast — one row per real change per scan).
	ChangeLogDays int `koanf:"change_log_days"`
	// DeviceNeighborsDays is the retention window for device_neighbors (L2
	// adjacency edges — Bridge-MIB / LLDP). Default 90 (low write volume — one
	// row per real adjacency, refreshed by upsert — and high value for topology
	// history).
	DeviceNeighborsDays int `koanf:"device_neighbors_days"`
	// HostServicesDays is the retention window for host_services (classified
	// service identities). host_services is upserted, not appended, but rows
	// for gone-silent hosts linger. Default 30.
	HostServicesDays int `koanf:"host_services_days"`
	// HostTLSCertsDays is the retention window for host_tls_certs (the TLS
	// certificate chain rows). host_tls_certs is replaced per (ip, port) on
	// each successful scan, but a host that drops offline leaves its stale
	// cert chain behind. PEM payload is a few KB per row, so we default tighter
	// than host_services. Default 30.
	HostTLSCertsDays int `koanf:"host_tls_certs_days"`
	// SweepIntervalHours is how often the retention sweeper runs across all
	// tables. Default 6h — frequent enough that no table drifts far past its
	// window, rare enough to be negligible overhead.
	SweepIntervalHours int `koanf:"sweep_interval_hours"`
	// BatchSize caps rows deleted per single DELETE statement. Large one-shot
	// deletes on million-row tables hold the write lock too long and bloat WAL;
	// batching keeps each transaction small so WAL can checkpoint between batches.
	BatchSize int `koanf:"batch_size"`
}

type ServerConfig struct {
	Port int    `koanf:"port"`
	Host string `koanf:"host"`
	// ReadTimeout bounds how long the server waits for a client to send the
	// full request (headers + body). Default 15s; raise only if clients upload
	// very large bodies slowly (uploads use a separate streaming path).
	ReadTimeout string `koanf:"read_timeout"`
	// WriteTimeout bounds the full response lifetime. This MUST exceed the
	// slowest synchronous endpoint — primarily POST /scanner/scan, which can
	// run for minutes on large CIDRs. Default "5m". Set lower only if you
	// never run large synchronous scans (use the async task API instead).
	WriteTimeout string `koanf:"write_timeout"`
	// IdleTimeout bounds keep-alive idle connections. Default "120s".
	IdleTimeout string `koanf:"idle_timeout"`
}

type DatabaseConfig struct {
	SQLite SQLiteConfig `koanf:"sqlite"`
}

type SQLiteConfig struct {
	Path string `koanf:"path"`
}

type AuthConfig struct {
	JWTSecret            string `koanf:"jwt_secret"`
	TokenExpiry          string `koanf:"token_expiry"`
	InitialAdminPassword string `koanf:"initial_admin_password"`
	CookieDomain         string `koanf:"cookie_domain"`
	CookieSecure         bool   `koanf:"cookie_secure"`
	CookieSameSite       string `koanf:"cookie_same_site"`
	CookieMaxAge         string `koanf:"cookie_max_age"`
}

type HeartbeatConfig struct {
	DefaultInterval int `koanf:"default_interval"`
	Timeout         int `koanf:"timeout"`
	RetentionDays   int `koanf:"retention_days"`
}

type PrometheusConfig struct {
	Enabled     bool   `koanf:"enabled"`
	MetricsPath string `koanf:"metrics_path"`
}

type DashboardConfig struct {
	DataSourceType string `koanf:"data_source_type"`
	PrometheusURL  string `koanf:"prometheus_url"`
}

type StorageConfig struct {
	UploadPath  string `koanf:"upload_path"`
	MaxFileSize int64  `koanf:"max_file_size"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

type CORSConfig struct {
	AllowedOrigins []string `koanf:"allowed_origins"`
}

type RateLimitConfig struct {
	LoginPerMinute  float64 `koanf:"login_per_minute"`
	GlobalPerMinute float64 `koanf:"global_per_minute"`
	ScanPerMinute   float64 `koanf:"scan_per_minute"`
}

type SMTPConfig struct {
	Host        string `koanf:"host"`
	Port        int    `koanf:"port"`
	Username    string `koanf:"username"`
	Password    string `koanf:"password"`
	FromAddress string `koanf:"from_address"`
}

type ScannerConfig struct {
	Enabled            bool `koanf:"enabled"`
	MaxConcurrentScans int  `koanf:"max_concurrent_scans"`
	DefaultTimeout     int  `koanf:"default_timeout"`
	MaxConcurrentHosts int  `koanf:"max_concurrent_hosts"`
	// PerProbeTimeout bounds a SINGLE probe attempt (one SNMP Get, one TCP dial,
	// one HTTP fetch) in seconds. Distinct from default_timeout (which bounds
	// the whole per-host pipeline). Default 3s — keeps /24 scans fast even when
	// many hosts are unresponsive (each dead host fails in seconds, not minutes).
	PerProbeTimeout    int                    `koanf:"per_probe_timeout"`
	RetentionDays      int                    `koanf:"retention_days"`
	DefaultCronExpr    string                 `koanf:"default_cron_expr"`
	PipelineDefaults   PipelineDefaultsConfig `koanf:"pipeline_defaults"`
	Engine             string                 `koanf:"engine"` // "v1" (legacy) or "v2" (new); default "v1" during transition
	PersistRawEvidence bool                   `koanf:"persist_raw_evidence"`
	// OUIPath points to the IEEE OUI vendor-mapping file used by the ARP probe
	// to derive a vendor from a MAC address. Optional; when empty or missing,
	// the MAC is still recorded but no vendor is attached. Override with the
	// MIBEE_SCANNER_OUI_PATH env var.
	OUIPath string `koanf:"oui_path"`
	// FingerprintPath points to a directory of fingerprint YAML rule files
	// (see configs/fingerprints/ + docs/fingerprint-spec.md). When empty, the
	// engine uses the rules embedded in the binary (zero-config). Override with
	// MIBEE_SCANNER_FINGERPRINT_PATH.
	FingerprintPath string `koanf:"fingerprint_path"`
	// SNMPCommunity is the default community string for the SNMP probe
	// (default "public" if empty). Override with MIBEE_SCANNER_SNMP_COMMUNITY.
	SNMPCommunity string `koanf:"snmp_community"`
	// RouterARP enables cross-subnet MAC resolution. When populated, the scanner
	// walks these routers' SNMP ARP tables (ipNetToMediaPhysAddress) to find MACs
	// for hosts the scanner can't reach at L2. The community defaults to
	// SNMPCommunity when empty.
	RouterARP RouterARPConfig `koanf:"router_arp"`
	EBPF      EBPFConfig      `koanf:"ebpf"`
	// Discovery enables the long-running passive discovery service that spots
	// newly-appeared hosts without a full subnet scan. It periodically walks a
	// router's SNMP ARP table + diffs the local /proc/net/arp cache + passively
	// listens for mDNS/SSDP, and feeds new hosts into the runner's device bridge
	// (so they get change-detection + heartbeat seeding). See DiscoveryConfig.
	Discovery DiscoveryConfig `koanf:"discovery"`
	// AgentLeaseTTL is how long an agent-managed device's snapshot may stay
	// stale (no agent report refreshing it) before the lease sweeper declares
	// it lost. Go duration string (e.g. "5m"). Default "5m" — ~10 missed
	// reports at the agent's 30s cadence, absorbing agent restarts/splits.
	AgentLeaseTTL string `koanf:"agent_lease_ttl"`
	// LeaseSweepInterval is how often the background lease sweeper runs the
	// expiration pass over agent-managed networks. Go duration string. Default
	// "60s". Center-only; the agent does not run a sweeper.
	LeaseSweepInterval string `koanf:"lease_sweep_interval"`
}

// RouterARPConfig configures cross-subnet MAC resolution via SNMP ARP walks of
// routers on the target subnets.
type RouterARPConfig struct {
	Routers   []string `koanf:"routers"`
	Community string   `koanf:"community"`
	Timeout   int      `koanf:"timeout"` // seconds; default 4
}

// EBPFConfig controls the passive eBPF observer (v2 engine only). Even with
// Enabled=true, the observer is a no-op unless the binary was built with the
// WITH_EBPF tag (see Makefile build-with-ebpf).
type EBPFConfig struct {
	Enabled    bool     `koanf:"enabled"`
	Interfaces []string `koanf:"interfaces"`
}

// DiscoveryConfig controls the long-running passive discovery service. Unlike
// the cron-driven full-subnet scan, this service runs continuously with near-
// zero active traffic: it diffs router/local ARP tables and passively listens
// for mDNS/SSDP, feeding newly-seen hosts into the runner's device bridge so
// they get device_added events + heartbeat seeding without waiting for the next
// scheduled scan. Each source can be toggled independently.
type DiscoveryConfig struct {
	// Enabled gates the whole service. When false, no passive discovery runs.
	Enabled bool `koanf:"enabled"`
	// Interval is the polling cadence (seconds) for the ARP-based sources.
	// Default 60. The multicast source is event-driven (listens continuously),
	// so this only affects router_arp + arp_cache.
	Interval int `koanf:"interval"`
	// TriggerIdentify, when true, runs a single-IP full identification scan
	// (the existing probe set) against each newly-discovered host so it gets a
	// type + services immediately. When false, the host is recorded with
	// inferred_type="unknown" and a bare ICMP heartbeat. Default true.
	TriggerIdentify bool `koanf:"trigger_identify"`
	// RouterARP walks scanner.router_arp.routers' SNMP ARP tables (the widest-
	// coverage source — a gateway knows every host that talks through it).
	// No-op when scanner.router_arp.routers is empty.
	RouterARP DiscoverySourceToggle `koanf:"router_arp"`
	// ARPCache diffs the local /proc/net/arp kernel cache. Zero network
	// traffic; only covers hosts the scanner host has talked to.
	ARPCache DiscoverySourceToggle `koanf:"arp_cache"`
	// Multicast passively listens on mDNS (224.0.0.251:5353) + SSDP
	// (239.255.255.250:1900) WITHOUT sending queries. Covers hosts that
	// self-advertise (cameras/printers/IoT/Mac/UPnP).
	Multicast DiscoverySourceToggle `koanf:"multicast"`
	// LLDPInterfaces is the list of NIC names for the raw-frame LLDPDU listener
	// (ethertype 0x88cc). Empty = all UP non-loopback interfaces. Only active in
	// WITH_LLDP builds (needs CAP_NET_RAW); no-op in the default build.
	LLDPInterfaces []string `koanf:"lldp_interfaces"`
}

// DiscoverySourceToggle is the per-source on/off switch for DiscoveryConfig.
type DiscoverySourceToggle struct {
	Enabled bool `koanf:"enabled"`
}

type PipelineDefaultsConfig struct {
	ICMPEnabled             bool   `koanf:"icmp_enabled"`
	SNMPEnabled             bool   `koanf:"snmp_enabled"`
	PortScanEnabled         bool   `koanf:"port_scan_enabled"`
	DefaultPorts            string `koanf:"default_ports"`
	ServiceDetectionEnabled bool   `koanf:"service_detection_enabled"`
	PrometheusCheckEnabled  bool   `koanf:"prometheus_check_enabled"`
	NodeExporterEnabled     bool   `koanf:"node_exporter_enabled"`
}

// Load reads configuration from a YAML file and overrides with environment variables.
func Load(configPath string) (*Config, error) {
	k := koanf.New(".")

	// Load YAML file
	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return nil, err
		}
	}

	// Load env vars with MIBEE_ prefix
	if err := k.Load(env.Provider("MIBEE_", ".", func(s string) string {
		return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(s, "MIBEE_")), "_", ".")
	}), nil); err != nil {
		return nil, err
	}

	// Unmarshal into Config
	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	// Apply retention defaults (and the scanner.retention_days back-compat
	// fallback for scan_results) before validation.
	normalizeRetention(&cfg)
	// Apply passive-discovery defaults (interval, trigger_identify, per-source
	// toggles). Done before validation so the service sees a fully-populated cfg.
	normalizeDiscovery(&cfg)

	// Validate
	if err := Validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// normalizeRetention fills in default retention windows for any field left at
// 0 by the config. A 0 in the YAML means "use the default", NOT "keep forever"
// — these detail tables are never meant to be retained indefinitely.
//
// Back-compat: the legacy scanner.retention_days (and heartbeat.retention_days)
// settings still drive their respective tables if the new retention.* key isn't
// set, so existing deployments keep their configured behavior on upgrade.
func normalizeRetention(cfg *Config) {
	r := &cfg.Retention
	if r.HeartbeatResultsDays <= 0 {
		// Fall back to legacy heartbeat.retention_days if set, else default 7.
		if cfg.Heartbeat.RetentionDays > 0 {
			r.HeartbeatResultsDays = cfg.Heartbeat.RetentionDays
		} else {
			r.HeartbeatResultsDays = 7
		}
	}
	if r.ScanResultsDays <= 0 {
		// Fall back to legacy scanner.retention_days if set, else default 30.
		if cfg.Scanner.RetentionDays > 0 {
			r.ScanResultsDays = cfg.Scanner.RetentionDays
		} else {
			r.ScanResultsDays = 30
		}
	}
	if r.ScanTaskRunsDays <= 0 {
		r.ScanTaskRunsDays = 30
	}
	if r.AuditLogsDays <= 0 {
		r.AuditLogsDays = 90
	}
	if r.NotificationLogDays <= 0 {
		r.NotificationLogDays = 30
	}
	if r.ServiceEvidenceDays <= 0 {
		r.ServiceEvidenceDays = 14
	}
	if r.ChangeLogDays <= 0 {
		r.ChangeLogDays = 30
	}
	if r.DeviceNeighborsDays <= 0 {
		r.DeviceNeighborsDays = 90
	}
	if r.HostServicesDays <= 0 {
		r.HostServicesDays = 30
	}
	if r.HostTLSCertsDays <= 0 {
		r.HostTLSCertsDays = 30
	}
	if r.SweepIntervalHours <= 0 {
		r.SweepIntervalHours = 6
	}
	if r.BatchSize <= 0 {
		r.BatchSize = 5000
	}
}

// normalizeDiscovery fills in passive-discovery defaults for any field left at
// its zero value. Only Interval is normalized here (0 → 60s). The boolean
// fields (Enabled, TriggerIdentify, the per-source toggles) keep their Go zero
// value (false) when unset, so the recommended defaults are surfaced through
// configs/config.example.yaml rather than silently applied — this respects a
// user's explicit `false` instead of clobbering it.
func normalizeDiscovery(cfg *Config) {
	d := &cfg.Scanner.Discovery
	if !d.Enabled {
		return
	}
	if d.Interval <= 0 {
		d.Interval = 60
	}
}

// Validate checks the configuration for errors.
func Validate(cfg *Config) error {
	// Agent mode (center URL set) doesn't serve users/SPA, so it has no JWT,
	// no admin seed, no auth cookie surface. Validate the agent-specific bits
	// instead and skip the center-only checks below.
	if cfg.Center.URL != "" {
		if cfg.Center.AuthToken == "" {
			return errors.New("center.auth_token is required in agent mode (mint one on the center via POST /api/v1/agents/tokens)")
		}
		if cfg.Network.Name == "" {
			return errors.New("network.name is required in agent mode (must match the network the token is bound to)")
		}
		return nil
	}

	// Center / standalone mode: validate JWT secret
	if cfg.Auth.JWTSecret == "" {
		return errors.New("auth.jwt_secret is required")
	}
	if len(cfg.Auth.JWTSecret) < 32 {
		return errors.New("auth.jwt_secret must be at least 32 characters long")
	}
	if cfg.Auth.JWTSecret == "change-me-in-production" {
		return errors.New("auth.jwt_secret must be changed from the default value")
	}

	// Validation warnings for insecure configurations
	if !cfg.Auth.CookieSecure {
		fmt.Fprintf(os.Stderr, "WARNING: auth.cookie_secure is false — cookies will be sent over HTTP. Set true for production.\n")
	}
	for _, origin := range cfg.CORS.AllowedOrigins {
		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			fmt.Fprintf(os.Stderr, "WARNING: CORS allowed_origins contains localhost (%s) — remove for production.\n", origin)
		}
	}

	return nil
}
