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

	// Validate
	if err := Validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
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
