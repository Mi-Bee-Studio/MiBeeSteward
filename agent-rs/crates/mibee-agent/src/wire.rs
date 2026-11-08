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
    /// Probe modules this binary can execute (#604); the center's dispatcher
    /// holds back plans for modules an agent never declared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_modules: Vec<String>,
    /// The host's DETECTED IPv4 on-link subnets (#686) — where the agent
    /// actually sits, as opposed to network_cidr (the configured claim).
    /// Empty on detection failure and on older agents (field absent = old
    /// wire shape, byte-compatible).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub self_interfaces: Vec<SelfInterface>,
}

/// Go `domain.AgentSelfInterface` (inside AgentMeta, #686).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SelfInterface {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cidr: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub primary: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
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
    /// The device's own port census (#529, IF-MIB + ipAddrTable) - the only
    /// channel the center's device_interfaces table sees from agent-side
    /// collection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<ReportedInterface>,
    /// Routing-table rows (#528, ipRouteTable) - next-hop-resolvable routes
    /// materialize route-table topology edges on the center.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<ReportedRoute>,
}

/// One port-census row (Go domain.ReportedInterface). if_index is the
/// center-side merge key (device_interfaces upsert).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReportedInterface {
    pub if_index: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub if_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub if_descr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    /// Link speed in Mbps.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub speed: i64,
}

/// One routing-table row (Go domain.ReportedRoute).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReportedRoute {
    pub dest: String,
    pub next_hop: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub if_index: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proto: String,
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

/// `probe` command payload (plan push, fingerprint-guarded). The trace block
/// (#719) rides the plan for agents that declared the `trace` capability;
/// absent = tracing disabled on this agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbePlanCommand {
    #[serde(default)]
    pub targets: Vec<ProbeTargetSpec>,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<TracePlan>,
}

/// Agent-side path-trace schedule (#719): which categories to trace and how.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TracePlan {
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub interval_minutes: i64,
    #[serde(default)]
    pub max_ttl: i64,
    #[serde(default)]
    pub per_hop_ms: i64,
}

/// `egress` command payload (#718): the echo-source set + cadence,
/// fingerprint-guarded like probe plans. Empty sources = rounds disabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EgressPlanCommand {
    #[serde(default)]
    pub sources: Vec<EgressSourceSpec>,
    #[serde(default)]
    pub interval_seconds: i64,
    #[serde(default)]
    pub fingerprint: String,
}

/// One echo source as pushed by the center (Go config.ProbeEgressSource).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EgressSourceSpec {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String, // http | stun | dns
    #[serde(default)]
    pub target: String,
}

/// Go `probetarget.Spec`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbeTargetSpec {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub module: String, // icmp | http | tls | tcp | dns
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub interval_seconds: i64,
    #[serde(default)]
    pub timeout_seconds: i64,
    #[serde(default)]
    pub vantage: String,
    /// Management category derived center-side (lan | external | quality) so
    /// the trace plan's allow-list needs no agent-side replication (#719).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<ProbeTargetOptions>,
}

/// Go `domain.ProbeOptions` (#605) — per-module execution options riding the
/// plan spec. Fields only apply to their own module; the center validates
/// the gating before shipping, the agent just executes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProbeTargetOptions {
    // http
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String, // GET | HEAD
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_status: Vec<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyword: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyword_mode: String, // contains | not_contains | regex
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_tls_errors: bool,
    // dns
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub record: String, // A | AAAA | CNAME | TXT
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resolver: String, // host[:port]; empty = system nameserver
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_ips: Vec<String>,
    // tcp
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub send: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expect: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expect_mode: String, // contains | regex
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

/// One egress round in an /agents/egress-report batch (#718). Raw echo
/// outcomes — origin-ASN enrichment happens on the center.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EgressRoundReport {
    pub round_at: String, // RFC3339 UTC, agent clock
    #[serde(default)]
    pub local: EgressLocalReport,
    #[serde(default)]
    pub results: Vec<EgressResultReport>,
}

/// The local-egress layer of one round (default-route view).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EgressLocalReport {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub iface: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway_ip: String,
    /// Reported for forward-compat; the center does not persist it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway_mac: String,
}

/// One echo source's outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EgressResultReport {
    pub source: String,
    pub kind: String,
    pub ok: bool,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub ms: f64,
    #[serde(default)]
    pub err: String,
}

/// One path trace in an /agents/path-report batch (#719).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PathSampleReport {
    pub target_id: i64,
    #[serde(default)]
    pub target_name: String,
    #[serde(default)]
    pub resolved_ip: String,
    #[serde(default)]
    pub method: String,
    pub end_state: String, // reached | max_ttl | error
    #[serde(default)]
    pub reached_ttl: i64,
    #[serde(default)]
    pub reply_ttl: i64,
    #[serde(default)]
    pub visible_hops: i64,
    #[serde(default)]
    pub hops: Vec<PathHopReport>,
    #[serde(default)]
    pub trigger: String, // baseline | failure
    #[serde(default)]
    pub err: String,
    pub traced_at: String, // RFC3339 UTC, agent clock
}

/// One responding hop; silent TTLs carry an empty ip.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PathHopReport {
    pub ttl: i64,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub ms: f64,
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
