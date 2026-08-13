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
	// Security holds process-wide secrets settings. Today this is the master
	// key used to encrypt SNMPv3 USM passphrases at rest (see internal/crypto).
	// Unlike auth.jwt_secret, the master key is OPTIONAL at startup: existing
	// deployments without it keep working for v1/v2c scans; it only becomes
	// required when the first SNMPv3 credential is created or read.
	Security SecurityConfig `koanf:"security"`
	// RBAC holds role-based access control tuning. Today this is the object-
	// level network-scope mode (#138 Phase 2): whether a non-admin user without
	// any network grants sees all networks ("open", default, preserves single-
	// team deployments) or nothing ("closed", MSP / multi-tenant isolation).
	RBAC RBACConfig `koanf:"rbac"`
}

// SecurityConfig carries the process-wide secret keying material. The master
// key protects secrets stored in SQLite (SNMPv3 USM auth/priv passphrases).
// Set it via the security.master_key YAML key or MIBEE_SECURITY_MASTER_KEY.
type SecurityConfig struct {
	// MasterKey is the raw AES-256 master key used by internal/crypto.Cipher.
	// It MUST be exactly 32 bytes. It is held in memory only (never persisted).
	// Leave empty to disable v3 credential storage (v1/v2c scans are unaffected).
	// Once any v3 credential exists in the DB, this key becomes required: change
	// it and the existing passphrases can no longer be decrypted (re-encrypt
	// them first via the migration path).
	MasterKey string `koanf:"master_key"`
}

// RBACConfig tunes role-based access control. ScopeDefault controls object-level
// network scope for non-admin users (#138 Phase 2):
//   - "open" (default): a non-admin user sees EVERY network (current behavior).
//     Network grants are ignored for visibility (still recorded for future use).
//   - "closed": a non-admin user sees ONLY the networks they hold a grant for
//     (MSP / multi-tenant isolation). Admin always bypasses scope.
//
// Set via rbac.scope_default YAML or MIBEE_RBAC_SCOPE_DEFAULT. Unknown values
// fall back to "open" (fail-safe against accidental lockout).
type RBACConfig struct {
	ScopeDefault string `koanf:"scope_default"`
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
	// DeviceLivenessDays is the retention window for device_liveness (the
	// per-device online/offline verdict series). It must be long enough to cover
	// the longest multi-period window the change engine queries (24h trend), so
	// the default matches heartbeat_results (7d). The series is disposable
	// (devices.status is source of truth), so a tight window is fine.
	DeviceLivenessDays  int `koanf:"device_liveness_days"`
	ScanResultsDays     int `koanf:"scan_results_days"`
	ScanTaskRunsDays    int `koanf:"scan_task_runs_days"`
	AuditLogsDays       int `koanf:"audit_logs_days"`
	NotificationLogDays int `koanf:"notification_log_days"`
	ServiceEvidenceDays int `koanf:"service_evidence_days"`
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
	// SilentDeviceDaysMAC is how long a scanner-discovered device WITH a MAC
	// address can stay offline (no heartbeat — all probe configs failing) before
	// the silent-device retention sweep physically deletes it (issue #117). MAC-
	// bearing devices are real assets that may genuinely disappear for a while
	// (laptop on a long trip, IoT device powered off), so the window is generous
	// (7d). A device that comes back online (5 consecutive successful probe
	// cycles) clears offline_since and the clock resets. Manual devices
	// (scan_source != 'scanner_v2') are NEVER auto-deleted. 0 → default 7.
	SilentDeviceDaysMAC int `koanf:"silent_device_days_mac"`
	// SilentDeviceHoursNoMAC is the same window for scanner-discovered devices
	// WITHOUT a MAC (mac_address=''). A mac-less device is an unreliable identity
	// (could be a transient/duplicate discovery), so it's pruned much faster
	// (24h) to keep the registry clean. 0 → default 24.
	SilentDeviceHoursNoMAC int `koanf:"silent_device_hours_no_mac"`
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
	// TrustedProxies is the list of CIDRs (or bare IPs) authorized to set
	// X-Forwarded-For. When the TCP peer is inside one of these networks, the
	// RealIP middleware takes the leftmost X-Forwarded-For entry as the client
	// IP (for rate limiting / audit logs). Empty (default) = trust NO proxy:
	// the TCP peer is the client — the safe default for direct exposure.
	// Populate with your reverse proxy's source range when deployed behind
	// nginx/another proxy (e.g. ["127.0.0.1/32"] for localhost nginx).
	TrustedProxies []string `koanf:"trusted_proxies"`
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
	// TickIntervalSeconds is the cadence of the heartbeat probing loop in
	// seconds (default 30). The loop polls every device whose heartbeat config
	// is due and writes verdicts to the in-memory status cache. Distinct from
	// DefaultInterval (which is the per-device probe interval stored in
	// heartbeat_configs.interval_seconds and feeds the isDue window) — that
	// value is also defaulted to TickIntervalSeconds when 0, so out of the box
	// a device is probed once per tick. Operators with large fleets or tight
	// RTT budgets can lower the tick for faster liveness detection or raise it
	// to reduce probe load. 0 means "use the default" (30s).
	TickIntervalSeconds int `koanf:"tick_interval_seconds"`
	// OfflineThreshold is the number of consecutive probe failures before a
	// device flips to "offline" (default 5). Together with scanner.lost_threshold
	// it defines the full death-detection behavior: this knob is the
	// heartbeat-side (probe-based) sensitivity, lost_threshold is the scan-side
	// (absence-based) sensitivity. Lower = more responsive but more flap-prone;
	// higher = more stable but slower to declare dead. 0 means "use the default".
	OfflineThreshold int `koanf:"offline_threshold"`
	// OfflineBackoffTicks throttles probing of devices already marked offline.
	// A value of N means an offline device is probed once every N ticks instead
	// of every tick (default 10 → on a 30s ticker that's ~5min between probes
	// for known-dead hosts vs 30s for live ones). This stops the steady write
	// of timeout rows into heartbeat_results for devices that won't answer
	// (the test env had 81 offline devices still probed every 30s). A scan that
	// revives a host clears its failure count + flips status back to online, so
	// backoff never delays real recovery detection. 0 disables backoff (probe
	// every tick, the old behavior).
	OfflineBackoffTicks int `koanf:"offline_backoff_ticks"`
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

// ScannerConfig and its sub-types (RouterARPConfig, RDNSConfig, MDNSConfig,
// ARPScanConfig, EBPFConfig, DiscoveryConfig, PipelineDefaultsConfig, etc.)
// live in scanner_config.go — extracted to keep this file manageable. (#160)

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
	normalizeRBAC(&cfg)

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
	if r.DeviceLivenessDays <= 0 {
		// Mirror heartbeat_results: the liveness series needs to cover the
		// longest multi-period window the change engine queries (24h trend), so
		// 7d is plenty. Default to the heartbeat window when unset.
		r.DeviceLivenessDays = r.HeartbeatResultsDays
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
	if r.SilentDeviceDaysMAC <= 0 {
		r.SilentDeviceDaysMAC = 7
	}
	if r.SilentDeviceHoursNoMAC <= 0 {
		r.SilentDeviceHoursNoMAC = 24
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

// normalizeRBAC canonicalizes rbac.scope_default. Empty or unrecognized values
// fall back to "open" — the non-lockout, backward-compatible default (a non-admin
// with no grants sees every network, preserving existing single-team installs).
// The canonical string values mirror domain.ScopeModeOpen/Closed (source of
// truth); config keeps to raw strings to avoid a config→domain dependency.
func normalizeRBAC(cfg *Config) {
	switch strings.ToLower(cfg.RBAC.ScopeDefault) {
	case "open", "closed":
		cfg.RBAC.ScopeDefault = strings.ToLower(cfg.RBAC.ScopeDefault)
	default:
		cfg.RBAC.ScopeDefault = "open"
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

	// security.master_key protects SNMPv3 USM passphrases at rest. It is
	// OPTIONAL (so existing deployments keep working for v1/v2c) but MUST be
	// exactly 32 bytes when set — a short key would silently weaken the
	// encryption, and internal/crypto.NewCipher rejects anything other than 32.
	// We warn here rather than fail so a config without v3 credentials isn't
	// blocked at startup; the hard error surfaces at first v3 credential use.
	if cfg.Security.MasterKey != "" && len(cfg.Security.MasterKey) != 32 {
		fmt.Fprintf(os.Stderr,
			"WARNING: security.master_key must be exactly 32 bytes long (got %d). "+
				"SNMPv3 credential storage will be unavailable until it is corrected.\n",
			len(cfg.Security.MasterKey))
	}
	if cfg.Security.MasterKey == "" {
		fmt.Fprintf(os.Stderr, "NOTE: security.master_key is not set — SNMPv3 credential storage disabled (v1/v2c scans unaffected). Set it to a 32-byte value to enable v3.\n")
	}

	return nil
}
