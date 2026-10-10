//! Vantage prober: applies center-pushed probe plans locally (10s tick;
//! targets due immediately on first sight then every interval), batches
//! results (10s or 32 rows), drops-not-buffers on failure (Go
//! internal/agent/prober.go).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::center::CenterClient;
use crate::wire::{ProbeResultReport, ProbeTargetSpec};

const TICK: Duration = Duration::from_secs(10); // schedule + flush cadence
const BATCH_MAX: usize = 32;

pub struct Prober {
    plan_fingerprint: String,
    targets: Vec<ProbeTargetSpec>,
    /// target id -> next-due unix ms (absent + fresh = run immediately).
    due: std::collections::HashMap<i64, i64>,
    vantage: String,
}

impl Prober {
    pub fn new(vantage: String) -> Self {
        Prober {
            plan_fingerprint: String::new(),
            targets: Vec::new(),
            due: std::collections::HashMap::new(),
            vantage,
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.plan_fingerprint
    }

    /// Apply a plan (fingerprint-guarded; an empty list clears the plan).
    pub fn apply_plan(&mut self, fingerprint: &str, targets: Vec<ProbeTargetSpec>) {
        if fingerprint == self.plan_fingerprint {
            return;
        }
        self.plan_fingerprint = fingerprint.to_string();
        self.targets = targets;
        self.due.clear(); // every target becomes due immediately
    }

    /// One tick: run due targets.
    pub async fn tick(&mut self) -> Vec<ProbeResultReport> {
        let now = now_ms();
        let due_specs: Vec<ProbeTargetSpec> = self
            .targets
            .iter()
            .filter(|t| self.due.get(&t.id).map(|d| now >= *d).unwrap_or(true))
            .cloned()
            .collect();
        let mut out = Vec::with_capacity(due_specs.len());
        for spec in due_specs {
            let interval = if spec.interval_seconds > 0 { spec.interval_seconds as i64 } else { 300 };
            self.due.insert(spec.id, now + interval * 1000);
            out.push(run_probe(&spec, &self.vantage).await);
        }
        out
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Failure kind a probe executor can report: the center schema only accepts
/// success | fail | timeout, so errors must map onto fail/timeout.
#[derive(Debug)]
struct ProbeFailure {
    timeout: bool,
    message: String,
}

impl ProbeFailure {
    fn other(message: impl Into<String>) -> Self {
        ProbeFailure { timeout: false, message: message.into() }
    }
    fn timeout(message: impl Into<String>) -> Self {
        ProbeFailure { timeout: true, message: message.into() }
    }
}

impl From<String> for ProbeFailure {
    fn from(message: String) -> Self {
        ProbeFailure { timeout: false, message }
    }
}

/// Execute one probe spec (icmp | http | tls).
pub async fn run_probe(spec: &ProbeTargetSpec, vantage: &str) -> ProbeResultReport {
    let timeout = Duration::from_secs(if spec.timeout_seconds > 0 {
        spec.timeout_seconds as u64
    } else {
        5
    });
    let started = Instant::now();
    let mut report = ProbeResultReport {
        target_id: spec.id,
        vantage: vantage.to_string(),
        checked_at: crate::wire::now_rfc3339(),
        ..Default::default()
    };
    match spec.module.as_str() {
        "icmp" => match datagram_ping(&spec.target, timeout).await {
            Some(_ms) => report.status = "success".into(),
            None => {
                report.status = "timeout".into();
                report.error_message = "no echo reply".into();
            }
        },
        "http" => match http_probe(&spec.target, timeout).await {
            Ok(code) => {
                report.status_code = code as i64;
                if (200..400).contains(&code) {
                    report.status = "success".into();
                } else {
                    report.status = "fail".into();
                    report.error_message = format!("http status {code}");
                }
            }
            Err(f) => {
                report.status = if f.timeout { "timeout" } else { "fail" }.into();
                report.error_message = f.message;
            }
        },
        "tls" => match tls_probe(&spec.target, timeout).await {
            Ok((version, not_after, trusted)) if !version.is_empty() => {
                report.status = "success".into();
                report.tls_version = version;
                report.cert_not_after = not_after;
                report.cert_trusted = trusted;
            }
            Ok(_) => {
                report.status = "fail".into();
                report.error_message = "no tls session".into();
            }
            Err(e) => {
                report.status = "fail".into();
                report.error_message = e;
            }
        },
        other => {
            report.status = "fail".into();
            report.error_message = format!("unknown module {other:?}");
        }
    }
    // A fail that burned the whole timeout budget is a timeout (covers the
    // tls executor, which reports every handshake outcome as a plain Option).
    if report.status == "fail" && started.elapsed() >= timeout {
        report.status = "timeout".into();
    }
    report.latency_ms = (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
    report
}

async fn datagram_ping(target: &str, timeout: Duration) -> Option<()> {
    let ip: std::net::IpAddr = target.parse().ok()?;
    crate::engine::probes::datagram_ping(ip, timeout).await
}

async fn http_probe(target: &str, timeout: Duration) -> Result<u16, ProbeFailure> {
    let url = if target.starts_with("http") { target.to_string() } else { format!("http://{target}") };
    crate::tls_provider::ensure_tls_provider();
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| ProbeFailure::other(e.to_string()))?;
    let resp = client.get(&url).send().await.map_err(|e| {
        if e.is_timeout() {
            ProbeFailure::timeout(e.to_string())
        } else {
            ProbeFailure::other(e.to_string())
        }
    })?;
    Ok(resp.status().as_u16())
}

async fn tls_probe(
    target: &str,
    timeout: Duration,
) -> Result<(String, String, Option<bool>), String> {
    let (host, port) = parse_host_port(target, 443).map_err(|e| e)?;
    match crate::engine::probes::tls_cert_probe(&host, port, timeout).await {
        Some(fields) => {
            let version = match fields.get("_version") {
                Some(v) if v == "1.3" => "TLSv1.3".to_string(),
                Some(_) => "TLSv1.2".to_string(),
                None => String::new(),
            };
            let not_after = fields.get("not_after").cloned().unwrap_or_default();
            let trusted = fields.get("self_signed").map(|s| s != "true");
            Ok((version, not_after, trusted))
        }
        None => Ok((String::new(), String::new(), None)),
    }
}

fn parse_host_port(target: &str, default_port: u16) -> Result<(String, u16), String> {
    let t = target.trim_start_matches("https://").trim_start_matches("http://");
    if let Some((h, p)) = t.rsplit_once(':') {
        if let Ok(port) = p.parse() {
            return Ok((h.to_string(), port));
        }
    }
    Ok((t.to_string(), default_port))
}

/// Unified background loop: schedule tick + batch flush, drop on failure.
pub async fn run_prober(
    prober: Arc<tokio::sync::Mutex<Prober>>,
    client: Arc<CenterClient>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut batch: Vec<ProbeResultReport> = Vec::new();
    let mut last_flush = Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {
                let reports = prober.lock().await.tick().await;
                batch.extend(reports);
            }
            _ = stop.changed() => {
                let tail = prober.lock().await.tick().await;
                batch.extend(tail);
                if !batch.is_empty() {
                    let _ = client.post_probe_results(&batch).await;
                }
                return;
            }
        }
        if batch.len() >= BATCH_MAX || (last_flush.elapsed() >= TICK && !batch.is_empty()) {
            match client.post_probe_results(&batch).await {
                Ok(accepted) => {
                    let _ = accepted;
                }
                Err(e) => eprintln!("prober: batch dropped: {}", e.0),
            }
            batch.clear();
            last_flush = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plan_apply_dedups_by_fingerprint() {
        let mut p = Prober::new("agent:x".into());
        p.apply_plan("f1", vec![ProbeTargetSpec { id: 1, module: "http".into(), target: "127.0.0.1:1".into(), interval_seconds: 3600, ..Default::default() }]);
        assert_eq!(p.targets.len(), 1);
        let before = p.due.clone();
        p.apply_plan("f1", vec![]); // same fingerprint: no-op
        assert_eq!(p.targets.len(), 1);
        assert_eq!(p.due, before);
        p.apply_plan("f2", vec![]); // new fingerprint clears the plan
        assert!(p.targets.is_empty());
    }

    #[tokio::test]
    async fn http_probe_runs_against_local_listener() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
            }
        });
        let code = http_probe(&format!("127.0.0.1:{port}"), Duration::from_secs(2)).await.unwrap();
        assert_eq!(code, 204);
    }

    #[tokio::test]
    async fn unknown_module_reports_error() {
        let spec = ProbeTargetSpec {
            id: 9,
            module: "carrier-pigeon".into(),
            target: "192.0.2.1".into(),
            ..Default::default()
        };
        let r = run_probe(&spec, "agent:t").await;
        assert_eq!(r.status, "fail");
        assert!(r.error_message.contains("carrier-pigeon"));
    }

    /// spawn a TCP listener answering every request with `status` after `delay_ms`
    async fn spawn_status_server(status_line: &'static str, delay_ms: u64) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                let _ = s.write_all(
                    format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                ).await;
            }
        });
        port
    }

    fn assert_schema_status(status: &str) {
        assert!(
            matches!(status, "success" | "fail" | "timeout"),
            "status {status:?} is rejected by the center CHECK constraint"
        );
    }

    #[tokio::test]
    async fn probe_statuses_stay_within_center_schema() {
        // 500 response -> fail (was "error", which the center rejects with 500
        // and drops the whole agent batch)
        let port = spawn_status_server("500 Internal Server Error", 0).await;
        let spec = ProbeTargetSpec {
            id: 1,
            module: "http".into(),
            target: format!("127.0.0.1:{port}"),
            timeout_seconds: 5,
            ..Default::default()
        };
        let r = run_probe(&spec, "agent:t").await;
        assert_schema_status(&r.status);
        assert_eq!(r.status, "fail");
        assert_eq!(r.status_code, 500);

        // unreachable port (bound-then-dropped) -> schema-legal status; the
        // exact fail/timeout split depends on how fast the OS returns the
        // RST (delayed RSTs burn the budget and legitimately read timeout)
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = l.local_addr().unwrap().port();
        drop(l);
        let spec = ProbeTargetSpec {
            id: 2,
            module: "http".into(),
            target: format!("127.0.0.1:{closed}"),
            timeout_seconds: 2,
            ..Default::default()
        };
        let r = run_probe(&spec, "agent:t").await;
        assert_schema_status(&r.status);
        assert!(r.latency_ms > 0.0);
    }

    #[tokio::test]
    async fn slow_response_beyond_timeout_maps_to_timeout() {
        let port = spawn_status_server("204 No Content", 1500).await;
        let spec = ProbeTargetSpec {
            id: 3,
            module: "http".into(),
            target: format!("127.0.0.1:{port}"),
            timeout_seconds: 1,
            ..Default::default()
        };
        let r = run_probe(&spec, "agent:t").await;
        assert_eq!(r.status, "timeout");
        assert!(r.latency_ms >= 1000.0);
    }

    #[tokio::test]
    async fn latency_measures_the_probe_not_the_setup() {
        // regression: latency was sampled before the probe ran and always
        // reported ~0.1ms
        let port = spawn_status_server("204 No Content", 120).await;
        let spec = ProbeTargetSpec {
            id: 4,
            module: "http".into(),
            target: format!("127.0.0.1:{port}"),
            timeout_seconds: 5,
            ..Default::default()
        };
        let r = run_probe(&spec, "agent:t").await;
        assert_eq!(r.status, "success");
        assert!(r.latency_ms >= 100.0, "latency_ms {} too small", r.latency_ms);
    }
}
