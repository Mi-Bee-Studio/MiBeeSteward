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

type ScannerConfig struct {
	Enabled            bool `koanf:"enabled"`
	MaxConcurrentScans int  `koanf:"max_concurrent_scans"`
	DefaultTimeout     int  `koanf:"default_timeout"`
	MaxConcurrentHosts int  `koanf:"max_concurrent_hosts"`
	// LostThreshold is the number of consecutive scans a device must be absent
	// from the alive set before being declared "lost" (default 2). Single
	// missed scans (ICMP drop, brief host downtime, network jitter) must not
	// flap a device offline — see architecture-future.md §8 note 3 (去抖动/grace
	// period). This is the scan-side (absence-based) death sensitivity; the
	// heartbeat-side (probe-based) sensitivity is heartbeat.offline_threshold.
	// 0 means "use the default" (2). Applied by DetectLost (runner), shared by
	// the local scan path + the agent→center ingestion path + the lease sweeper.
	LostThreshold int `koanf:"lost_threshold"`
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
	// RDNS tunes the reverse-DNS probe (active:rdns). By default the probe uses
	// the system resolver (/etc/resolv.conf), which on a center box often points
	// at a public DNS with no view into the LAN's DHCP-synthesized PTR records —
	// so hostnames are missed for devices that DO have a PTR on the local DNS.
	// Populating RDNS.DNSServers (e.g. the router/LAN DNS IP) makes the probe
	// query those servers directly for PTR records, dramatically improving
	// hostname coverage on networks where the local DNS knows the hosts but the
	// center's system resolver doesn't. Issue #20.
	RDNS RDNSConfig `koanf:"rdns"`
	// MDNS tunes the mDNS probe (active:mdns). UnicastQueries reaches devices
	// that answer unicast mDNS but not multicast. Issue #20.
	MDNS MDNSConfig `koanf:"mdns"`
	// ARPScan is the active ARP-sweep source: it broadcasts ARP who-has requests
	// for every IP in the local subnet and emits a NewHostEvent for each reply.
	// Unlike router_arp (needs SNMP) or arp_cache (passive read), this needs no
	// router access and covers the whole broadcast domain — every host MUST
	// answer ARP. Needs CAP_NET_RAW + the WITH_ARPSCAN build tag; the toggle in
	// Discovery.ARPScan gates it, but it remains a no-op in the default build.
	ARPScan ARPScanConfig `koanf:"arp_scan"`
	EBPF    EBPFConfig    `koanf:"ebpf"`
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
	// ReconcileInterval is how often the background network-attribution
	// reconciliation job runs (issue #19 Layer 3). The job detects devices whose
	// IP falls outside their stamped network's CIDR — the bottom-line defense
	// that catches drift the Layer 1/2 boundary checks miss. Go duration string.
	// Default "1h" (it's a low-frequency audit, not a hot path). Center-only.
	ReconcileInterval string `koanf:"reconcile_interval"`
}

// RouterARPConfig configures cross-subnet MAC resolution via SNMP ARP walks of
// routers on the target subnets.
type RouterARPConfig struct {
	Routers   []string `koanf:"routers"`
	Community string   `koanf:"community"`
	Timeout   int      `koanf:"timeout"` // seconds; default 4
}

// RDNSConfig tunes the reverse-DNS probe. DNSServers (optional) overrides the
// system resolver: when set, the rDNS probe queries ONLY these servers (typical
// use: the LAN's router/DNS that holds DHCP-synthesized PTR records the center's
// /etc/resolv.conf can't reach). Empty = use the system resolver (current
// behavior). Each entry is host or host:port (port defaults to 53). Issue #20.
type RDNSConfig struct {
	DNSServers []string `koanf:"dns_servers"`
	// Timeout is the per-lookup deadline in seconds. Default 2.
	Timeout int `koanf:"timeout"`
}

// MDNSConfig tunes the mDNS probe. UnicastQueries makes the probe also send a
// unicast mDNS query to each target's 5353 port (in addition to the multicast
// query), reaching devices that answer unicast but not multicast. Issue #20.
type MDNSConfig struct {
	UnicastQueries bool `koanf:"unicast_queries"`
}

// ARPScanConfig configures the active ARP-sweep discovery source. Interface is
// the NIC to send who-has frames on (empty = auto-select the interface whose
// IPv4 falls inside the center's network CIDR). The sweep cadence reuses
// Discovery.Interval (no separate interval here) so all ARP sources stay in
// lockstep.
type ARPScanConfig struct {
	Interface string `koanf:"interface"`
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
	// ARPScan actively broadcasts ARP who-has requests for every host in the
	// center's network CIDR and emits a NewHostEvent per reply. The widest-
	// coverage source that needs NO router access (every host must answer ARP).
	// No-op in default builds (needs WITH_ARPSCAN + CAP_NET_RAW); the toggle has
	// effect only in a WITH_ARPSCAN build.
	ARPScan DiscoverySourceToggle `koanf:"arp_scan"`
	// DHCPLeases reads the local DHCP server's lease table (dnsmasq's
	// /tmp/dhcp.leases on OpenWrt / /var/lib/misc/dnsmasq.leases on Debian). A
	// Tier-1 router-resident signal: the gateway is the DHCP authority, so its
	// lease table is the authoritative hostname↔MAC↔IP map — covering devices
	// (sleeping IoT, firewalled hosts) that never answer SNMP/ICMP/rDNS. No-op
	// on a host that isn't the LAN's DHCP server (file absent → source skips).
	DHCPLeases DiscoverySourceToggle `koanf:"dhcp_leases"`
	// Conntrack reads the kernel conntrack table (/proc/net/nf_conntrack) and
	// emits the LAN-side endpoint of every ESTABLISHED/ASSURED flow. A Tier-1
	// router-resident signal: the gateway is the NAT choke point, so its
	// conntrack table is the authoritative "who is talking RIGHT NOW" view — a
	// liveness + discovery source for hosts that don't answer active probes but
	// maintain outbound flows. Filters to the local LAN CIDR (network.cidr) so
	// it doesn't emit a row per public IP a device talks to. No-op when the
	// nf_conntrack module isn't loaded or /proc/net/nf_conntrack is absent.
	Conntrack DiscoverySourceToggle `koanf:"conntrack"`
	// Hostapd enumerates the WiFi STAs associated to the local AP(s) via the
	// hostapd control socket (/var/run/hostapd/<phy>), falling back to
	// `iw station dump`. A Tier-1 router/AP-only signal: signal dBm, connect
	// time, SSID are GOLD for device tracking and completely unavailable to a
	// wired host-based scanner. No-op on a host without WiFi / hostapd / iw.
	Hostapd HostapdDiscoveryConfig `koanf:"hostapd"`
	// DNSLog tails a dnsmasq query log (--log-queries output) and emits the
	// querying host per DNS query — a powerful passive fingerprint (devices that
	// block all inbound probes still make outbound DNS). A Tier-1 router signal:
	// the gateway is typically the LAN's recursive resolver. No-op when dnsmasq
	// query logging isn't configured (no log file at the conventional paths).
	DNSLog DNSLogDiscoveryConfig `koanf:"dns_log"`
	// LLDPInterfaces is the list of NIC names for the raw-frame LLDPDU listener
	// (ethertype 0x88cc). Empty = all UP non-loopback interfaces. Only active in
	// WITH_LLDP builds (needs CAP_NET_RAW); no-op in the default build.
	LLDPInterfaces []string `koanf:"lldp_interfaces"`
}

// DiscoverySourceToggle is the per-source on/off switch for DiscoveryConfig.
type DiscoverySourceToggle struct {
	Enabled bool `koanf:"enabled"`
}

// HostapdDiscoveryConfig configures the WiFi STA enumeration source. Interfaces
// is the list of wlan names to poll (e.g. ["wlan0", "wlan1"]); when empty the
// source autodetects (probes /var/run/hostapd/* sockets, falls back to "wlan0"
// for the iw station-dump path).
type HostapdDiscoveryConfig struct {
	Enabled    bool     `koanf:"enabled"`
	Interfaces []string `koanf:"interfaces"`
}

// DNSLogDiscoveryConfig configures the dnsmasq query-log tail source. Path
// overrides the log file location (dnsmasq --log-facility output); when empty
// the source probes the conventional paths (/var/log/dnsmasq.log, /tmp/dnsmasq.log,
// syslog). The operator must enable dnsmasq query logging (UCI:
// `uci set dhcp.@dnsmasq[0].logqueries=1`).
type DNSLogDiscoveryConfig struct {
	Enabled bool   `koanf:"enabled"`
	Path    string `koanf:"path"`
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
