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
	// SNMPCommunity is the default community string for the SNMP probe
	// (default "public" if empty). Override with MIBEE_SCANNER_SNMP_COMMUNITY.
	SNMPCommunity string `koanf:"snmp_community"`
	// RouterARP enables cross-subnet MAC resolution. When populated, the scanner
	// walks these routers' SNMP ARP tables (ipNetToMediaPhysAddress) to find MACs
	// for hosts the scanner can't reach at L2. The community defaults to
	// SNMPCommunity when empty.
	RouterARP RouterARPConfig `koanf:"router_arp"`
	EBPF      EBPFConfig      `koanf:"ebpf"`
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
	if r.SweepIntervalHours <= 0 {
		r.SweepIntervalHours = 6
	}
	if r.BatchSize <= 0 {
		r.BatchSize = 5000
	}
}

// Validate checks the configuration for errors.
func Validate(cfg *Config) error {

	// Validate JWT secret
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
