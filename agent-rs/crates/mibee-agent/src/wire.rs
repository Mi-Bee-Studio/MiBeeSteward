//! Agent ↔ center wire types, byte-exact with the Go implementation
//! (`internal/domain/agent_report.go`, `internal/db/models.go` AgentCommand,
//! `internal/service/probetarget/dispatcher.go`). Golden tests pin the JSON.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Go `domain.AgentReport` (POST /api/v1/agents/report body).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentReport {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network_cidr: String,
    pub scanned_at: String, // RFC3339Nano UTC
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<AgentMeta>,
    /// Go marshals a nil slice as null (heartbeat batches carry hosts:null).
    #[serde(default)]
    pub hosts: Option<Vec<ReportedHost>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
}

/// Go `domain.AgentMeta`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentMeta {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub go_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub uptime_sec: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub scans_total: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint_rev: String,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

/// Go `domain.ReportedHost`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ReportedHost {
    pub ip: String,
    pub alive: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub rtt_ms: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inferred_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inferred_type_source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inferred_brand: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inferred_model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inferred_description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inferred_location: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    /// JSON-in-string (raw JSON text, stored verbatim by the center).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub open_ports: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detected_services: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prometheus_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_exporter_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ReportedService>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heartbeats: Vec<ReportedHeartbeat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snmp: Option<ReportedSnmp>,
    /// L2 adjacency edges (LLDP / CDP / Bridge-MIB / Q-BRIDGE / STP probes).
    /// The evidence array never crosses the wire; this is the only channel
    /// agent-side topology reaches the center through (Go domain.ReportedHost
    /// .Neighbors parity).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub neighbors: Vec<ReportedNeighbor>,
}

/// One L2 adjacency edge (Go domain.ReportedNeighbor). `neighbor_mac` +
/// `protocol` are required; the rest carry what the discovering protocol
/// announced.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReportedNeighbor {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub neighbor_mac: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_port: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_port: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vlan_tag: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_desc: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

/// Go `domain.ReportedService`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ReportedService {
    pub service: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub port: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Go `domain.ReportedHeartbeat`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ReportedHeartbeat {
    pub method: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub interval_seconds: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub timeout_seconds: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snmp_community: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub snmp_oid: String,
}

/// Go `domain.ReportedSNMP`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ReportedSnmp {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_descr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_object_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_location: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_contact: String,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub sys_services: i32,
}

/// Center ack for a report POST.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ReportAck {
    #[serde(default)]
    pub accepted: i64,
    #[serde(default)]
    pub added: i64,
    #[serde(default)]
    pub updated: i64,
    #[serde(default)]
    pub skipped: i64,
    #[serde(default)]
    pub out_of_network: i64,
    #[serde(default)]
    pub stable: bool,
}

/// GET /api/v1/agents/commands row. `payload` is a double-encoded JSON
/// string (the center stores the marshaled map as TEXT; the agent re-parses).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentCommand {
    pub id: i64,
    #[serde(default)]
    pub agent_id: String,
    pub command: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub acknowledged_at: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
}

/// `scan` command payload (inside the double-encoded string).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScanCommand {
    pub targets: String,
    #[serde(default)]
    pub timeout: i64,
    #[serde(default)]
    pub concurrent: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_name: String,
}

/// `probe` command payload (plan push, fingerprint-guarded).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbePlanCommand {
    #[serde(default)]
    pub targets: Vec<ProbeTargetSpec>,
    #[serde(default)]
    pub fingerprint: String,
}

/// Go `probetarget.Spec`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbeTargetSpec {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub module: String, // icmp | http | tls
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub interval_seconds: i64,
    #[serde(default)]
    pub timeout_seconds: i64,
    #[serde(default)]
    pub vantage: String,
}

/// POST /api/v1/agents/probe-report row — Go `probetarget.AgentResultReport`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbeResultReport {
    pub target_id: i64,
    #[serde(default)]
    pub vantage: String,
    pub status: String,
    #[serde(default)]
    pub latency_ms: f64,
    #[serde(default)]
    pub status_code: i64,
    #[serde(default)]
    pub error_message: String,
    #[serde(default)]
    pub tls_version: String,
    #[serde(default)]
    pub cert_not_after: String,
    #[serde(default)]
    pub cert_trusted: Option<bool>,
    #[serde(default)]
    pub checked_at: String, // RFC3339 UTC, agent clock
}

/// POST /api/v1/agents/commands/{id}/complete body.
#[derive(Debug, Clone, Serialize)]
pub struct CommandComplete {
    pub status: String, // "done" | "failed"
    pub result: String,
}

/// The anti-entropy header value: SHA-256 over hosts sorted by IP, each
/// contributing `ip, mac, inferred_type, inferred_brand, inferred_description,
/// inferred_location, hostname, open_ports, detected_services`, every field
/// followed by a NUL byte (Go reporter.go networkStateHash).
pub fn network_state_hash(hosts: &[ReportedHost]) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&ReportedHost> = hosts.iter().collect();
    sorted.sort_by(|a, b| a.ip.cmp(&b.ip));
    let mut h = Sha256::new();
    for host in sorted {
        for field in [
            &host.ip,
            &host.mac,
            &host.inferred_type,
            &host.inferred_brand,
            &host.inferred_description,
            &host.inferred_location,
            &host.hostname,
            &host.open_ports,
            &host.detected_services,
        ] {
            h.update(field.as_bytes());
            h.update([0u8]);
        }
    }
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Corpus revision: SHA-256 over sorted (filename, NUL, content, NUL) pairs
/// of every `*.yaml` in the corpus dir (Go fpsync.Hash); content-addressed,
/// order/mtime independent.
pub fn corpus_rev(dir: &str) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".yaml"))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut h = Sha256::new();
    for name in &names {
        let content = std::fs::read(std::path::Path::new(dir).join(name))?;
        h.update(name.as_bytes());
        h.update([0u8]);
        h.update(&content);
        h.update([0u8]);
    }
    Ok(hex(&h.finalize()))
}

/// Go `time.ParseDuration` subset the agent configs use: `<n>s|m|h` (also a
/// bare integer = seconds). 0 when unparsable (callers apply defaults).
pub fn duration_secs(v: &str) -> u64 {
    let v = v.trim();
    if v.is_empty() {
        return 0;
    }
    if v.contains(['s', 'm', 'h']) && !v.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        // unit suffix or compound like "1m30s" — walk segments
        let mut total = 0u64;
        let mut cur = String::new();
        for c in v.chars() {
            if c.is_ascii_digit() || c == '.' {
                cur.push(c);
            } else {
                let n: f64 = cur.parse().unwrap_or(0.0);
                let m = match c {
                    's' => 1,
                    'm' => 60,
                    'h' => 3600,
                    'd' => 86400,
                    _ => 0,
                };
                total += (n * m as f64) as u64;
                cur.clear();
            }
        }
        return total;
    }
    v.parse::<f64>().map(|n| n as u64).unwrap_or(0)
}

/// RFC3339 UTC timestamp for wire fields (Go marshals time.Time as
/// RFC3339Nano; millisecond precision parses identically center-side).
pub fn now_rfc3339() -> String {
    use chrono::Utc;
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
