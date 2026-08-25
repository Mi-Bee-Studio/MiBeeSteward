// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package config

// ScannerConfig and its sub-types were extracted from config.go to keep that
// file manageable (the scanner subsystem alone is ~230 lines of config types).
// All types here are plain data structs with koanf tags — no methods, no logic.

type ScannerConfig struct {
	Enabled            bool `koanf:"enabled"`
	MaxConcurrentScans int  `koanf:"max_concurrent_scans"`
	DefaultTimeout     int  `koanf:"default_timeout"`
	MaxConcurrentHosts int  `koanf:"max_concurrent_hosts"`
	// AllowReservedTargets is the escape hatch for the reserved-range scan
	// target rejection (#317). Default false: loopback / unspecified /
	// link-local / multicast / broadcast / 240-4 space is rejected at every
	// entry point — a scheduled loopback task once invented 1022 phantom
	// devices that resurrected daily. Set true ONLY for synthetic planes
	// (cmd/loadgen serves its benchmark fleet on 127/8, where the kernel
	// answers ICMP for free); config-file access is already admin-only.
	AllowReservedTargets bool `koanf:"allow_reserved_targets"`
	// LostThreshold is the number of consecutive scans a device must be absent
	// from the alive set before being declared "lost" (default 2). Single
	// missed scans (ICMP drop, brief host downtime, network jitter) must not
	// flap a device offline — see architecture-future.md §8 note 3 (去抖动/grace
	// period). This is the scan-side (absence-based) death sensitivity; the
	// heartbeat-side (probe-based) sensitivity is heartbeat.offline_threshold.
	// 0 means "use the default" (2). Applied by DetectLost (runner), shared by
	// the local scan path + the agent→center ingestion path + the lease sweeper.
	LostThreshold int `koanf:"lost_threshold"`
	// ConfigBackup configures the periodic device running-config backup (#137).
	// Disabled by default — requires security.master_key + at least one device
	// with an SSH credential bound. See BackupConfig.
	ConfigBackup BackupConfig `koanf:"config_backup"`
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
	// (see configs/fingerprints/ + docs/en/fingerprint-spec.md). When empty, the
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

// BackupConfig configures the device config-backup sweep (#137). The
// service fetches each router/switch/firewall device's running-config over SSH
// (using its bound ssh_credential), diffs it, and records a version when it
// changes. All fields default (0/empty) → "use sensible defaults"; Enabled
// defaults to false (opt-in — requires master_key + bound SSH credentials).
type BackupConfig struct {
	Enabled  bool `koanf:"enabled"`
	Interval int  `koanf:"interval_seconds"` // seconds between sweeps; <=0 → 6h
	Timeout  int  `koanf:"timeout_seconds"`  // per-device SSH timeout; <=0 → 30s
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
