//! Agent configuration: `-config` YAML + `MIBEE_`-prefixed env overrides,
//! mirroring the Go loader's koanf behavior for the keys the agent consumes
//! (agent-mode validation: `center.url` required/empty=fatal,
//! `center.auth_token` + `network.name` required; secrets never logged).

use std::path::Path;

use serde::Deserialize;

use crate::wire::duration_secs;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub center: CenterConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub scanner: ScannerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct CenterConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub auth_token: String,
    /// Duration string ("30s"); default 30.
    #[serde(default)]
    pub report_interval: String,
    #[serde(default)]
    pub remote_ops_enabled: bool,
    #[serde(default)]
    pub fingerprint_sync: FingerprintSyncConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct FingerprintSyncConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Duration string ("10m"); default 600, clamped >= 60.
    #[serde(default)]
    pub interval: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct NetworkConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub cidr: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct SecurityConfig {
    /// Exactly 32 bytes when set; empty disables the local vault.
    #[serde(default)]
    pub master_key: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct LogConfig {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default)]
    pub format: String,
}

fn default_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ScannerConfig {
    #[serde(default)]
    pub snmp_community: String,
    /// mDNS probe tuning (Go scanner.mdns parity, #504).
    #[serde(default)]
    pub mdns: MdnsConfig,
    /// Seconds (engine floor 30 when 0).
    #[serde(default)]
    pub default_timeout: i64,
    /// Seconds (default 3).
    #[serde(default)]
    pub per_probe_timeout: i64,
    #[serde(default)]
    pub max_concurrent_hosts: i64,
    #[serde(default)]
    pub max_concurrent_scans: i64,
    #[serde(default)]
    pub lost_threshold: i64,
    #[serde(default)]
    pub fingerprint_path: String,
    #[serde(default)]
    pub allow_reserved_targets: bool,
    #[serde(default)]
    pub persist_raw_evidence: bool,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub rdns: RdnsConfig,
    #[serde(default)]
    pub router_arp: RouterArpConfig,
}

/// mDNS probe options (Go MDNSConfig): unicast_queries additionally sends each
/// query straight to the target's 5353 port — for devices that answer unicast
/// mDNS but not multicast (#20).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct MdnsConfig {
    #[serde(default)]
    pub unicast_queries: bool,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DiscoveryConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Poll cadence seconds (default 60).
    #[serde(default)]
    pub interval: i64,
    #[serde(default)]
    pub trigger_identify: bool,
    #[serde(default)]
    pub arp_cache: SourceToggle,
    #[serde(default)]
    pub multicast: SourceToggle,
    #[serde(default)]
    pub dhcp_leases: SourceToggle,
    #[serde(default)]
    pub conntrack: SourceToggle,
    /// router_arp passive source: periodic SNMP walk of
    /// scanner.router_arp.routers (widest coverage; community path only,
    /// Go agent parity — v3 there is a later enhancement).
    #[serde(default)]
    pub router_arp: SourceToggle,
    #[serde(default)]
    pub hostapd: HostapdConfig,
    /// dns_log source (Go DNSLogDiscoveryConfig): tails dnsmasq --log-queries
    /// output; each LAN host's queries are host sightings + domain seeds.
    /// No-op when the log file is absent (dnsmasq query logging not enabled).
    #[serde(default)]
    pub dns_log: DnsLogConfig,
}

/// dns_log source options (Go DNSLogDiscoveryConfig). Path empty = probe the
/// conventional dnsmasq log paths.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DnsLogConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: String,
}

/// hostapd WiFi STA source (Go HostapdDiscoveryConfig): ctrl-socket walk
/// with an `iw station dump` fallback. Empty interfaces = autodetect
/// (/var/run/hostapd/* + the wlan0 default for iw).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct HostapdConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub interfaces: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct SourceToggle {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RdnsConfig {
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouterArpConfig {
    #[serde(default)]
    pub routers: Vec<String>,
    #[serde(default)]
    pub community: String,
    /// Per-request SNMP timeout seconds (0 → the scanner per-probe default).
    #[serde(default)]
    pub timeout: i64,
}

impl Config {
    /// Load YAML, apply `MIBEE_` env overrides, validate agent-mode
    /// requirements. Returns a descriptive error on any failure.
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read config {path}: {e}"))?;
        let mut cfg: Config =
            serde_yaml::from_str(&text).map_err(|e| format!("parse config {path}: {e}"))?;
        apply_env_overrides(&mut cfg)?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    fn normalize(&mut self) {
        if self.scanner.snmp_community.is_empty() {
            self.scanner.snmp_community = "public".to_string();
        }
        if self.scanner.default_timeout <= 0 {
            self.scanner.default_timeout = 30;
        }
        if self.scanner.per_probe_timeout <= 0 {
            self.scanner.per_probe_timeout = 3;
        }
        if self.scanner.max_concurrent_hosts <= 0 {
            self.scanner.max_concurrent_hosts = 50;
        }
        if self.scanner.max_concurrent_scans < 0 {
            self.scanner.max_concurrent_scans = 0; // 0 = unbounded (Go parity)
        }
        if self.scanner.lost_threshold <= 0 {
            self.scanner.lost_threshold = 2;
        }
        if self.scanner.discovery.interval <= 0 {
            self.scanner.discovery.interval = 60;
        }
        if !self.center.fingerprint_sync.interval.is_empty()
            && duration_secs(&self.center.fingerprint_sync.interval) < 60
        {
            self.center.fingerprint_sync.interval = "60s".to_string();
        } else if self.center.fingerprint_sync.interval.is_empty() {
            self.center.fingerprint_sync.interval = "10m".to_string();
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.center.url.is_empty() {
            return Err("center.url is required in agent mode".to_string());
        }
        if self.center.auth_token.is_empty() {
            return Err(
                "center.auth_token is required in agent mode (mint one on the center via POST /api/v1/agents/tokens)"
                    .to_string(),
            );
        }
        if self.network.name.is_empty() {
            return Err("network.name is required in agent mode".to_string());
        }
        if !self.network.cidr.is_empty() {
            if self.network.cidr.parse::<ipnet::Ipv4Net>().is_err() {
                return Err(format!("network.cidr {:?} is not a valid IPv4 network", self.network.cidr));
            }
        }
        if !self.security.master_key.is_empty() && self.security.master_key.len() != 32 {
            return Err(format!(
                "security.master_key must be exactly 32 bytes (got {}); the local SNMPv3 vault stays disabled",
                self.security.master_key.len()
            ));
        }
        Ok(())
    }

    /// Where the local agent.db lives: next to the config file (Go parity).
    pub fn db_path(config_path: &str) -> String {
        let dir = Path::new(config_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default();
        dir.join("agent.db").to_string_lossy().into_owned()
    }

    /// Fingerprint corpus precedence: scanner.fingerprint_path →
    /// <configdir>/fingerprints-sync → embedded.
    pub fn fingerprint_dir(&self, config_path: &str) -> Option<String> {
        if !self.scanner.fingerprint_path.is_empty() {
            return Some(self.scanner.fingerprint_path.clone());
        }
        let dir = Path::new(config_path)
            .parent()
            .map(|p| p.join("fingerprints-sync"))
            .unwrap_or_default();
        if dir.is_dir() {
            return Some(dir.to_string_lossy().into_owned());
        }
        None
    }

    pub fn report_interval_secs(&self) -> u64 {
        let v = duration_secs(&self.center.report_interval);
        if v == 0 {
            30
        } else {
            v
        }
    }

    pub fn fingerprint_sync_secs(&self) -> u64 {
        duration_secs(&self.center.fingerprint_sync.interval).max(60)
    }
}

/// `MIBEE_X_Y` → `x.y` with underscore→dot splitting (Go koanf blind path),
/// applied AFTER YAML load, exactly like the Go env provider.
fn apply_env_overrides(cfg: &mut Config) -> Result<(), String> {
    for (k, v) in std::env::vars() {
        let Some(rest) = k.strip_prefix("MIBEE_") else { continue };
        let lower = rest.to_ascii_lowercase();
        if lower.is_empty() {
            continue;
        }
        let path: Vec<&str> = lower.split('_').collect();
        apply_path(cfg, &path, &v)?;
    }
    Ok(())
}

fn apply_path(cfg: &mut Config, path: &[&str], value: &str) -> Result<(), String> {
    let bool_val = |v: &str| match v {
        "true" | "1" => Ok(true),
        "false" | "0" | "" => Ok(false),
        other => Err(format!("bad bool env value {other:?}")),
    };
    match path {
        ["center", "url"] => cfg.center.url = value.to_string(),
        ["center", "auth", "token"] => cfg.center.auth_token = value.to_string(),
        ["center", "report", "interval"] => cfg.center.report_interval = value.to_string(),
        ["center", "remote", "ops", "enabled"] => cfg.center.remote_ops_enabled = bool_val(value)?,
        ["center", "fingerprint", "sync", "enabled"] => {
            cfg.center.fingerprint_sync.enabled = bool_val(value)?
        }
        ["center", "fingerprint", "sync", "interval"] => {
            cfg.center.fingerprint_sync.interval = value.to_string()
        }
        ["network", "name"] => cfg.network.name = value.to_string(),
        ["network", "cidr"] => cfg.network.cidr = value.to_string(),
        ["security", "master", "key"] => cfg.security.master_key = value.to_string(),
        ["log", "level"] => cfg.log.level = value.to_string(),
        ["log", "format"] => cfg.log.format = value.to_string(),
        ["scanner", "snmp", "community"] => cfg.scanner.snmp_community = value.to_string(),
        ["scanner", "default", "timeout"] => {
            cfg.scanner.default_timeout = value.parse().map_err(|_| "bad int".to_string())?
        }
        ["scanner", "per", "probe", "timeout"] => {
            cfg.scanner.per_probe_timeout = value.parse().map_err(|_| "bad int".to_string())?
        }
        ["scanner", "max", "concurrent", "hosts"] => {
            cfg.scanner.max_concurrent_hosts = value.parse().map_err(|_| "bad int".to_string())?
        }
        ["scanner", "max", "concurrent", "scans"] => {
            cfg.scanner.max_concurrent_scans = value.parse().map_err(|_| "bad int".to_string())?
        }
        ["scanner", "fingerprint", "path"] => cfg.scanner.fingerprint_path = value.to_string(),
        ["scanner", "allow", "reserved", "targets"] => {
            cfg.scanner.allow_reserved_targets = bool_val(value)?
        }
        ["scanner", "discovery", "enabled"] => cfg.scanner.discovery.enabled = bool_val(value)?,
        ["scanner", "discovery", "interval"] => {
            cfg.scanner.discovery.interval = value.parse().map_err(|_| "bad int".to_string())?
        }
        ["scanner", "discovery", "dhcp", "leases"] => {
            cfg.scanner.discovery.dhcp_leases.enabled = bool_val(value)?
        }
        ["scanner", "discovery", "arp", "cache"] => {
            cfg.scanner.discovery.arp_cache.enabled = bool_val(value)?
        }
        ["scanner", "discovery", "multicast"] => {
            cfg.scanner.discovery.multicast.enabled = bool_val(value)?
        }
        ["scanner", "discovery", "conntrack"] => {
            cfg.scanner.discovery.conntrack.enabled = bool_val(value)?
        }
        ["scanner", "discovery", "router", "arp"] => {
            cfg.scanner.discovery.router_arp.enabled = bool_val(value)?
        }
        ["scanner", "router", "arp", "routers"] => {
            cfg.scanner.router_arp.routers =
                value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        }
        ["scanner", "router", "arp", "community"] => {
            cfg.scanner.router_arp.community = value.to_string()
        }
        ["scanner", "router", "arp", "timeout"] => {
            cfg.scanner.router_arp.timeout = value.parse().map_err(|_| "bad int".to_string())?
        }
        ["scanner", "discovery", "hostapd"] => {
            cfg.scanner.discovery.hostapd.enabled = bool_val(value)?
        }
        ["scanner", "discovery", "hostapd", "interfaces"] => {
            cfg.scanner.discovery.hostapd.interfaces =
                value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        }
        // Unknown keys are ignored (koanf's blind env mapping only maps
        // keys the struct knows; silently skipping keeps parity).
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn write_cfg(text: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.yaml");
        std::fs::write(&p, text).unwrap();
        // keep the dir alive past this fn (tests read it right after)
        std::mem::forget(dir);
        p.to_string_lossy().into_owned()
    }

    const MINIMAL: &str = "center:\n  url: \"http://center.example:8080\"\n  auth_token: \"a0b1c2d3\"\nnetwork:\n  name: lan-63\n  cidr: \"192.0.2.0/24\"\n";

    #[test]
    #[serial]
    fn minimal_config_loads() {
        let cfg = Config::load(&write_cfg(MINIMAL)).unwrap();
        assert_eq!(cfg.center.url, "http://center.example:8080");
        assert_eq!(cfg.network.name, "lan-63");
        assert_eq!(cfg.scanner.snmp_community, "public"); // normalized
        assert_eq!(cfg.scanner.default_timeout, 30);
        assert_eq!(cfg.scanner.per_probe_timeout, 3);
        assert_eq!(cfg.scanner.max_concurrent_hosts, 50);
        assert_eq!(cfg.report_interval_secs(), 30);
    }

    #[test]
    #[serial]
    fn router_arp_section_parses() {
        let cfg = Config::load(&write_cfg(&format!(
            "{MINIMAL}scanner:
  router_arp:
    routers: [\"192.0.2.1\", \"192.0.2.2\"]
    community: \"lanro\"
    timeout: 5
  discovery:
    enabled: true
    router_arp:
      enabled: true
"
        )))
        .unwrap();
        assert_eq!(cfg.scanner.router_arp.routers, vec!["192.0.2.1", "192.0.2.2"]);
        assert_eq!(cfg.scanner.router_arp.community, "lanro");
        assert_eq!(cfg.scanner.router_arp.timeout, 5);
        assert!(cfg.scanner.discovery.router_arp.enabled);
    }

    #[test]
    #[serial]
    fn router_arp_env_override() {
        let path = write_cfg(&format!("{MINIMAL}scanner:
  router_arp:
    routers: [\"192.0.2.1\"]
"));
        std::env::set_var("MIBEE_SCANNER_ROUTER_ARP_ROUTERS", "192.0.2.9, 192.0.2.8");
        std::env::set_var("MIBEE_SCANNER_DISCOVERY_ROUTER_ARP", "true");
        let cfg = Config::load(&path).unwrap();
        std::env::remove_var("MIBEE_SCANNER_ROUTER_ARP_ROUTERS");
        std::env::remove_var("MIBEE_SCANNER_DISCOVERY_ROUTER_ARP");
        assert_eq!(cfg.scanner.router_arp.routers, vec!["192.0.2.9", "192.0.2.8"]);
        assert!(cfg.scanner.discovery.router_arp.enabled);
    }

    #[test]
    #[serial]
    fn missing_url_is_fatal() {
        let err = Config::load(&write_cfg("center:\n  auth_token: x\nnetwork:\n  name: n\n")).unwrap_err();
        assert!(err.contains("center.url"), "{err}");
    }

    #[test]
    #[serial]
    fn missing_token_or_network_rejected() {
        let err = Config::load(&write_cfg("center:\n  url: \"http://x:1\"\nnetwork:\n  name: n\n")).unwrap_err();
        assert!(err.contains("auth_token"));
        let err = Config::load(&write_cfg("center:\n  url: \"http://x:1\"\n  auth_token: t\n")).unwrap_err();
        assert!(err.contains("network.name"));
    }

    #[test]
    #[serial]
    fn master_key_length_enforced() {
        let err = Config::load(&write_cfg(
            "center:\n  url: \"http://x:1\"\n  auth_token: t\nnetwork:\n  name: n\nsecurity:\n  master_key: short\n",
        ))
        .unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    #[serial]
    fn bad_cidr_rejected() {
        let err = Config::load(&write_cfg(
            "center:\n  url: \"http://x:1\"\n  auth_token: t\nnetwork:\n  name: n\n  cidr: \"not-a-cidr\"\n",
        ))
        .unwrap_err();
        assert!(err.contains("cidr"));
    }

    #[test]
    #[serial]
    fn env_override_wins_over_yaml() {
        let path = write_cfg(MINIMAL);
        // SAFETY: tests run multi-threaded; isolate via a lock.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap();
        std::env::set_var("MIBEE_NETWORK_NAME", "lan-62");
        std::env::set_var("MIBEE_SCANNER_DISCOVERY_DHCP_LEASES", "true");
        let cfg = Config::load(&path).unwrap();
        std::env::remove_var("MIBEE_NETWORK_NAME");
        std::env::remove_var("MIBEE_SCANNER_DISCOVERY_DHCP_LEASES");
        assert_eq!(cfg.network.name, "lan-62");
        assert!(cfg.scanner.discovery.dhcp_leases.enabled);
    }

    #[test]
    #[serial]
    fn db_and_fingerprint_paths() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("agent.yaml");
        std::fs::write(&p, MINIMAL).unwrap();
        let ps = p.to_string_lossy().into_owned();
        assert!(Config::db_path(&ps).ends_with("agent.db"));
        assert!(Config::db_path(&ps).contains(dir.path().to_str().unwrap()));
        let cfg = Config::load(&ps).unwrap();
        assert_eq!(cfg.fingerprint_dir(&ps), None); // no synced dir yet
        let sync = dir.path().join("fingerprints-sync");
        std::fs::create_dir(&sync).unwrap();
        assert!(cfg.fingerprint_dir(&ps).unwrap().ends_with("fingerprints-sync"));
    }

    #[test]
    #[serial]
    fn fingerprint_sync_interval_clamped() {
        let cfg = Config::load(&write_cfg(
            "center:\n  url: \"http://x:1\"\n  auth_token: t\n  fingerprint_sync:\n    enabled: true\n    interval: \"30s\"\nnetwork:\n  name: n\n",
        ))
        .unwrap();
        assert_eq!(cfg.fingerprint_sync_secs(), 60); // clamped >= 60
    }
}
