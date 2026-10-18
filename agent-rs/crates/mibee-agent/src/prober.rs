//! Vantage prober: applies center-pushed probe plans locally (10s tick;
//! targets due on a deterministic first-stagger then every interval), batches
//! results (10s or 32 rows), and parks-not-drops failed batches (bounded
//! oldest-first queue + retry ladder, the reporter's #554 pattern).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::center::CenterClient;
use crate::wire::{ProbeResultReport, ProbeTargetOptions, ProbeTargetSpec};

const TICK: Duration = Duration::from_secs(10); // schedule + flush cadence
const BATCH_MAX: usize = 32;
/// Failed-report park queue bound (batches, oldest dropped first) — mirrors
/// the reporter's pending cap.
const PENDING_MAX: usize = 100;
/// Base retry backoff for one batch (1s→2s→4s→8s ladder, 4 attempts).
const RETRY_BACKOFF: Duration = Duration::from_secs(1);
/// HTTP keyword inspection bound (matches the center's 1 MiB body limit).
const BODY_LIMIT: usize = 1 << 20;

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
    /// Every target's first run is staggered deterministically over the
    /// first minute so a fresh plan (or a plan re-push after a fingerprint
    /// change) does not march in lockstep (#604 jitter).
    pub fn apply_plan(&mut self, fingerprint: &str, targets: Vec<ProbeTargetSpec>) {
        if fingerprint == self.plan_fingerprint {
            return;
        }
        self.plan_fingerprint = fingerprint.to_string();
        self.targets = targets;
        self.due.clear();
        let now = now_ms();
        for t in &self.targets {
            let interval = if t.interval_seconds > 0 { t.interval_seconds } else { 300 };
            self.due.insert(t.id, now + stagger_ms(t.id, interval));
        }
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
            let interval = if spec.interval_seconds > 0 { spec.interval_seconds } else { 300 };
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

/// Deterministic first-run spread: hash(id) within min(interval, 60s). Same
/// id always maps to the same offset, so re-pushes and tests are stable.
fn stagger_ms(id: i64, interval_secs: i64) -> i64 {
    let span = interval_secs.clamp(1, 60);
    (id.wrapping_mul(2654435761)).rem_euclid(span) * 1000
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
        ProbeFailure { timeout: message.contains("timeout"), message }
    }
}

/// Execute one probe spec (icmp | http | tls | tcp | dns).
pub async fn run_probe(spec: &ProbeTargetSpec, vantage: &str) -> ProbeResultReport {
    let timeout = Duration::from_secs(if spec.timeout_seconds > 0 {
        spec.timeout_seconds as u64
    } else {
        5
    });
    let opts = spec.options.as_ref();
    let started = Instant::now();
    let mut report = ProbeResultReport {
        target_id: spec.id,
        vantage: vantage.to_string(),
        checked_at: crate::wire::now_rfc3339(),
        ..Default::default()
    };
    match spec.module.as_str() {
        "icmp" => match icmp_ping(&spec.target, timeout).await {
            Some(()) => report.status = "success".into(),
            None => {
                report.status = "timeout".into();
                report.error_message = "no echo reply".into();
            }
        },
        "http" => match http_probe(&spec.target, opts, timeout).await {
            Ok((code, body)) => {
                report.status_code = code as i64;
                let expected = opts.and_then(|o| {
                    if o.expected_status.is_empty() { None } else { Some(&o.expected_status) }
                });
                let status_ok = match expected {
                    Some(list) => list.contains(&(code as i64)),
                    None => (200..400).contains(&code),
                };
                if !status_ok {
                    report.status = "fail".into();
                    report.error_message = format!("http status {code} not in expected set");
                } else if let (Some(o), Some(body)) = (opts, body) {
                    match match_payload(&o.keyword_mode, &o.keyword, &body) {
                        Ok(true) => report.status = "success".into(),
                        Ok(false) => {
                            report.status = "fail".into();
                            report.error_message = keyword_fail_reason(&o.keyword_mode);
                        }
                        Err(e) => {
                            report.status = "fail".into();
                            report.error_message = e;
                        }
                    }
                } else {
                    report.status = "success".into();
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
                report.status = if e.contains("timeout") { "timeout" } else { "fail" }.into();
                report.error_message = e;
            }
        },
        "tcp" => match tcp_probe(&spec.target, opts, timeout).await {
            Ok(()) => report.status = "success".into(),
            Err(f) => {
                report.status = if f.timeout { "timeout" } else { "fail" }.into();
                report.error_message = f.message;
            }
        },
        "dns" => match dns_probe(&spec.target, opts, timeout).await {
            Ok(()) => report.status = "success".into(),
            Err(e) => {
                report.status = if e.contains("timeout") { "timeout" } else { "fail" }.into();
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

/// ICMP with hostname resolution (#604): IP literals connect directly, a
/// hostname resolves through the system resolver first.
async fn icmp_ping(target: &str, timeout: Duration) -> Option<()> {
    let ip: std::net::IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => crate::engine::probes::tls::resolve_host(target).await?,
    };
    crate::engine::probes::datagram_ping(ip, timeout).await
}

async fn http_probe(
    target: &str,
    opts: Option<&ProbeTargetOptions>,
    timeout: Duration,
) -> Result<(u16, Option<Vec<u8>>), ProbeFailure> {
    let url = if target.starts_with("http") { target.to_string() } else { format!("http://{target}") };
    crate::tls_provider::ensure_tls_provider();
    // TLS posture (#604): verify by default, center parity; the explicit
    // per-target opt-out is the only way to accept a broken cert.
    let ignore_tls = opts.map(|o| o.ignore_tls_errors).unwrap_or(false);
    let is_head = opts.map(|o| o.method.as_str()).unwrap_or("") == "HEAD";
    let method = if is_head { reqwest::Method::HEAD } else { reqwest::Method::GET };
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(ignore_tls)
        .build()
        .map_err(|e| ProbeFailure::other(e.to_string()))?;
    let resp = client.request(method, &url).send().await.map_err(|e| {
        if e.is_timeout() {
            ProbeFailure::timeout(e.to_string())
        } else {
            ProbeFailure::other(e.to_string())
        }
    })?;
    let code = resp.status().as_u16();
    let needs_body = opts.map(|o| !o.keyword.is_empty()).unwrap_or(false) && !is_head;
    let body = if needs_body {
        let mut buf: Vec<u8> = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp.chunk().await.map_err(|e| ProbeFailure::other(e.to_string()))? {
            if buf.len() + chunk.len() > BODY_LIMIT {
                buf.extend_from_slice(&chunk[..BODY_LIMIT.saturating_sub(buf.len())]);
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        Some(buf)
    } else {
        None
    };
    Ok((code, body))
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
            // Trusted verdict (#604): a REAL verifying handshake against the
            // webpki root store replaces the old self_signed approximation,
            // matching the center's two-pass chainIsTrusted.
            let trusted = crate::engine::probes::tls::tls_verify_handshake(&host, port, timeout)
                .await
                .is_ok();
            Ok((version, not_after, Some(trusted)))
        }
        None => Ok((String::new(), String::new(), None)),
    }
}

/// tcp module (#604/#605): connect (TcpStream resolves hostnames natively),
/// optionally write `send`, optionally match the banner against `expect`.
async fn tcp_probe(
    target: &str,
    opts: Option<&ProbeTargetOptions>,
    timeout: Duration,
) -> Result<(), ProbeFailure> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let sock = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target))
        .await
        .map_err(|_| ProbeFailure::timeout("connect timeout"))?
        .map_err(|e| ProbeFailure::from(e.to_string()))?;
    let mut sock = sock;
    if let Some(o) = opts {
        if !o.send.is_empty() {
            tokio::time::timeout(timeout, sock.write_all(o.send.as_bytes()))
                .await
                .map_err(|_| ProbeFailure::timeout("write timeout"))?
                .map_err(|e| ProbeFailure::other(format!("write payload: {e}")))?;
        }
        if !o.expect.is_empty() {
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(timeout, sock.read(&mut buf))
                .await
                .map_err(|_| ProbeFailure::timeout("read banner timeout"))?
                .map_err(|e| ProbeFailure::other(format!("read banner: {e}")))?;
            match match_payload(&o.expect_mode, &o.expect, &buf[..n]) {
                Ok(true) => {}
                Ok(false) => return Err(ProbeFailure::other("banner does not match expect")),
                Err(e) => return Err(ProbeFailure::other(e)),
            }
        }
    }
    Ok(())
}

/// dns module (#605): hand-rolled codec + one UDP round-trip, against the
/// pinned resolver or the system nameserver. expected_ips turns an answer
/// mismatch into a failure (A/AAAA only).
async fn dns_probe(
    target: &str,
    opts: Option<&ProbeTargetOptions>,
    timeout: Duration,
) -> Result<(), String> {
    use crate::engine::dns::{udp_query, RData};
    let (record, resolver, expected_ips) = match opts {
        Some(o) => (
            if o.record.is_empty() { "A".to_string() } else { o.record.clone() },
            o.resolver.clone(),
            o.expected_ips.clone(),
        ),
        None => ("A".to_string(), String::new(), Vec::new()),
    };
    let qtype = match record.as_str() {
        "A" => 1u16,
        "AAAA" => 28,
        "CNAME" => 5,
        "TXT" => 16,
        other => return Err(format!("unsupported dns record {other:?}")),
    };

    let addr = if resolver.is_empty() {
        let servers = crate::engine::probes::rdns::system_nameservers().await;
        match servers.first() {
            Some(s) => s.parse().map_err(|e| format!("bad system nameserver: {e}"))?,
            None => return Err("no system nameserver available".into()),
        }
    } else {
        parse_resolver(&resolver)?
    };
    let msg = udp_query(addr, target, qtype, timeout).await?;
    match msg.rcode {
        0 => {}
        3 => return Err("NXDOMAIN: no such host".into()),
        n => return Err(format!("dns rcode {n}")),
    }
    if !expected_ips.is_empty() && (qtype == 1 || qtype == 28) {
        let got: Vec<String> = msg
            .answers
            .iter()
            .filter_map(|rr| match &rr.rdata {
                RData::A(v4) if qtype == 1 => Some(v4.to_string()),
                RData::Aaaa(v6) if qtype == 28 => Some(v6.to_string()),
                _ => None,
            })
            .collect();
        let hit = expected_ips.iter().any(|w| got.iter().any(|g| g.eq_ignore_ascii_case(w)));
        if !hit {
            return Err(format!("resolved {got:?} does not intersect expected_ips {expected_ips:?}"));
        }
    }
    Ok(())
}

/// resolver "host" | "host:port" | "[v6]:port" → SocketAddr (53 implied).
fn parse_resolver(resolver: &str) -> Result<std::net::SocketAddr, String> {
    if let Ok(addr) = resolver.parse() {
        return Ok(addr);
    }
    if !resolver.contains(':') {
        return format!("{resolver}:53").parse().map_err(|e| format!("bad resolver: {e}"));
    }
    if resolver.starts_with('[') {
        return format!("{resolver}:53").parse().map_err(|e| format!("bad resolver: {e}"));
    }
    Err(format!("bad resolver {resolver:?}"))
}

/// Shared payload matcher for http keyword and tcp expect (#605, Go
/// matchPayload parity). Err carries e.g. an invalid regex.
fn match_payload(mode: &str, pattern: &str, payload: &[u8]) -> Result<bool, String> {
    match mode {
        "" | "contains" => Ok(payload.windows(pattern.len().max(1)).any(|w| w == pattern.as_bytes())),
        "not_contains" => Ok(!payload.windows(pattern.len().max(1)).any(|w| w == pattern.as_bytes())),
        "regex" => {
            let re = regex::bytes::Regex::new(pattern).map_err(|e| format!("invalid regex: {e}"))?;
            Ok(re.is_match(payload))
        }
        other => Err(format!("unknown match mode {other:?}")),
    }
}

/// Failure wording for a keyword/expect mismatch, mirroring the center's
/// matchPayload reasons (i18n lives in the UI, this is the stored row).
fn keyword_fail_reason(mode: &str) -> String {
    match mode {
        "not_contains" => "body contains forbidden keyword".into(),
        "regex" => "body does not match regex".into(),
        _ => "body does not contain keyword".into(),
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

/// Unified background loop: schedule tick, batch flush, park failed batches
/// (bounded, oldest-first) and retry one parked batch per tick — the
/// reporter's #554 pattern, no more drop-on-failure.
pub async fn run_prober(
    prober: Arc<tokio::sync::Mutex<Prober>>,
    client: Arc<CenterClient>,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    run_prober_with_tuning(prober, client, stop, RETRY_BACKOFF, TICK).await
}

/// Test surface: same loop with shrunken cadences.
pub async fn run_prober_with_tuning(
    prober: Arc<tokio::sync::Mutex<Prober>>,
    client: Arc<CenterClient>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    retry_backoff: Duration,
    tick: Duration,
) {
    let mut batch: Vec<ProbeResultReport> = Vec::new();
    let mut pending: Vec<Vec<ProbeResultReport>> = Vec::new(); // oldest-first
    let mut last_flush = Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick) => {
                let reports = prober.lock().await.tick().await;
                batch.extend(reports);
            }
            _ = stop.changed() => {
                let tail = prober.lock().await.tick().await;
                batch.extend(tail);
                if !batch.is_empty() {
                    let _ = post_with_retry(&client, &batch, retry_backoff).await;
                }
                // Parked batches stay parked across a stop: bounded memory,
                // retried after restart (Go parity with stop_flush).
                return;
            }
        }

        // One parked batch per tick, oldest first — recovery drains at one
        // batch per tick even while fresh results keep flowing.
        if !pending.is_empty() {
            let head = pending.remove(0);
            if post_with_retry(&client, &head, retry_backoff).await.is_err() {
                pending.insert(0, head);
            }
            continue;
        }

        if batch.len() >= BATCH_MAX || (last_flush.elapsed() >= tick && !batch.is_empty()) {
            if post_with_retry(&client, &batch, retry_backoff).await.is_err() {
                pending.push(std::mem::take(&mut batch));
                while pending.len() > PENDING_MAX {
                    pending.remove(0);
                }
                eprintln!("prober: batch parked (center unreachable), pending={}", pending.len());
            } else {
                batch.clear();
            }
            last_flush = Instant::now();
        }
    }
}

/// 4-attempt ladder (backoff, backoff*2, backoff*4, backoff*8). Ok = the
/// batch is gone (accepted, or 4xx terminal like the reporter treats 400/
/// 403/409); Err = transport exhausted → caller parks.
async fn post_with_retry(
    client: &CenterClient,
    batch: &[ProbeResultReport],
    base_backoff: Duration,
) -> Result<(), String> {
    let mut backoff = base_backoff;
    for attempt in 0..4 {
        match client.post_probe_results(batch).await {
            Ok(_) => return Ok(()),
            Err(e) if attempt == 3 => return Err(e.0),
            Err(e) => {
                eprintln!("prober: post attempt {} failed: {}", attempt + 1, e.0);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    unreachable!("loop returns on the 4th attempt")
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

    /// The stagger is deterministic and bounded by one minute.
    #[test]
    fn stagger_is_deterministic_and_bounded() {
        for id in [1i64, 7, 42, 999] {
            let a = stagger_ms(id, 300);
            assert_eq!(a, stagger_ms(id, 300));
            assert!(a >= 0 && a < 60_000, "id {id}: {a}");
        }
        // Different ids spread (not all the same offset).
        let offsets: std::collections::HashSet<i64> =
            (1..=20).map(|id| stagger_ms(id, 60)).collect();
        assert!(offsets.len() > 1);
    }

    #[tokio::test]
    async fn plan_apply_staggers_first_due() {
        let mut p = Prober::new("agent:x".into());
        p.apply_plan("f1", vec![ProbeTargetSpec {
            id: 33,
            module: "http".into(),
            target: "127.0.0.1:1".into(),
            interval_seconds: 3600,
            ..Default::default()
        }]);
        let due = *p.due.get(&33).expect("seeded on apply");
        let expected = stagger_ms(33, 3600);
        // Seeded at now+stagger; allow scheduling slack, assert NOT immediate.
        assert!(due > now_ms(), "first run must be staggered, not immediate");
        assert!(due <= now_ms() + expected + 2000);
        // Nothing due on the first tick because of the stagger.
        assert!(p.tick().await.is_empty());
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
        let (code, body) = http_probe(&format!("127.0.0.1:{port}"), None, Duration::from_secs(2)).await.unwrap();
        assert_eq!(code, 204);
        assert!(body.is_none());
    }

    /// keyword + expected_status semantics against a local responder.
    #[tokio::test]
    async fn http_options_semantics() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let body = b"healthy: all systems nominal";
                let _ = s.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
                )
                .await;
                let _ = s.write_all(body).await;
            }
        });
        let url = format!("127.0.0.1:{port}");
        let opts = |o: ProbeTargetOptions| Some(o);

        // Keyword hit + expected 200.
        let spec_ok = ProbeTargetSpec {
            id: 1,
            module: "http".into(),
            target: url.clone(),
            timeout_seconds: 5,
            options: opts(ProbeTargetOptions {
                keyword: "nominal".into(),
                expected_status: vec![200],
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = run_probe(&spec_ok, "agent:t").await;
        assert_eq!(r.status, "success");

        // Keyword miss → fail with the reason.
        let spec_miss = ProbeTargetSpec {
            id: 2,
            module: "http".into(),
            target: url.clone(),
            timeout_seconds: 5,
            options: opts(ProbeTargetOptions { keyword: "unhealthy".into(), ..Default::default() }),
            ..Default::default()
        };
        let r = run_probe(&spec_miss, "agent:t").await;
        assert_eq!(r.status, "fail");
        assert!(r.error_message.contains("does not contain"));

        // Expected-status miss beats keyword.
        let spec_status = ProbeTargetSpec {
            id: 3,
            module: "http".into(),
            target: url.clone(),
            timeout_seconds: 5,
            options: opts(ProbeTargetOptions {
                expected_status: vec![204],
                keyword: "nominal".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = run_probe(&spec_status, "agent:t").await;
        assert_eq!(r.status, "fail");
        assert!(r.error_message.contains("not in expected set"));

        // not_contains trips on presence.
        let spec_forbidden = ProbeTargetSpec {
            id: 4,
            module: "http".into(),
            target: url.clone(),
            timeout_seconds: 5,
            options: opts(ProbeTargetOptions {
                keyword: "healthy".into(),
                keyword_mode: "not_contains".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = run_probe(&spec_forbidden, "agent:t").await;
        assert_eq!(r.status, "fail");
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

    /// tcp module: connect-only, then send/expect against a line server.
    #[tokio::test]
    async fn tcp_module_connect_and_banner() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 64];
                let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut b))
                    .await
                    .unwrap_or(Ok(0))
                    .unwrap_or(0);
                if &b[..n] == b"HELLO" {
                    let _ = s.write_all(b"SSH-2.0-mibee\r\n").await;
                }
            }
        });

        let plain = ProbeTargetSpec {
            id: 1,
            module: "tcp".into(),
            target: addr.clone(),
            timeout_seconds: 3,
            ..Default::default()
        };
        assert_eq!(run_probe(&plain, "agent:t").await.status, "success");

        let banner = ProbeTargetSpec {
            id: 2,
            module: "tcp".into(),
            target: addr.clone(),
            timeout_seconds: 3,
            options: Some(ProbeTargetOptions {
                send: "HELLO".into(),
                expect: "SSH-2.0".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = run_probe(&banner, "agent:t").await;
        assert_eq!(r.status, "success");

        let mismatch = ProbeTargetSpec {
            id: 3,
            module: "tcp".into(),
            target: addr,
            timeout_seconds: 3,
            options: Some(ProbeTargetOptions {
                send: "HELLO".into(),
                expect: "FTP".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = run_probe(&mismatch, "agent:t").await;
        assert_eq!(r.status, "fail");
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
                )
                .await;
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

    #[test]
    fn resolver_parsing_shapes() {
        assert!(parse_resolver("223.5.5.5").unwrap().port() == 53);
        assert!(parse_resolver("223.5.5.5:5353").unwrap().port() == 5353);
        assert!(parse_resolver("[2001:db8::1]:53").is_ok());
        assert!(parse_resolver("udp://x").is_err());
    }

    /// Mock UDP DNS responder: answers every query with either one A record
    /// (93.184.216.34) or an NXDOMAIN, built with the codec's own encoder.
    async fn spawn_mock_dns(answer: Option<[u8; 4]>) -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
                let q = &buf[..n];
                if q.len() < 12 {
                    continue;
                }
                let mut reply = Vec::with_capacity(n + 16);
                reply.extend_from_slice(&q[..2]);
                let (flags, answers): ([u8; 2], u16) = match answer {
                    Some(_) => ([0x81, 0x80], 1),
                    None => ([0x81, 0x83], 0), // NXDOMAIN
                };
                reply.extend_from_slice(&flags);
                reply.extend_from_slice(&[0, 1]); // qdcount
                reply.extend_from_slice(&answers.to_be_bytes());
                reply.extend_from_slice(&[0, 0, 0, 0]); // ns + ar
                reply.extend_from_slice(&q[12..n]); // question verbatim
                if let Some(rdata) = answer {
                    reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]); // ptr, A, IN
                    reply.extend_from_slice(&60u32.to_be_bytes()); // ttl
                    reply.extend_from_slice(&[0, 4]); // rdlen
                    reply.extend_from_slice(&rdata);
                }
                let _ = sock.send_to(&reply, peer).await;
            }
        });
        addr
    }

    /// dns module end to end against the mock resolver: plain lookup,
    /// expected_ips hit and miss, NXDOMAIN.
    #[tokio::test]
    async fn dns_module_against_mock_resolver() {
        let addr = spawn_mock_dns(Some([93, 184, 216, 34])).await;
        let mk = |expected_ips: Vec<&str>| ProbeTargetSpec {
            id: 5,
            module: "dns".into(),
            target: "example.com".into(),
            timeout_seconds: 3,
            options: Some(ProbeTargetOptions {
                record: "A".into(),
                resolver: addr.clone(),
                expected_ips: expected_ips.into_iter().map(String::from).collect(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let r = run_probe(&mk(vec![]), "agent:t").await;
        assert_eq!(r.status, "success", "{}", r.error_message);

        let r = run_probe(&mk(vec!["93.184.216.34"]), "agent:t").await;
        assert_eq!(r.status, "success");

        let r = run_probe(&mk(vec!["1.1.1.1"]), "agent:t").await;
        assert_eq!(r.status, "fail");
        assert!(r.error_message.contains("expected_ips"), "{}", r.error_message);

        let nxdomain = spawn_mock_dns(None).await;
        let spec = ProbeTargetSpec {
            id: 6,
            module: "dns".into(),
            target: "missing.example".into(),
            timeout_seconds: 3,
            options: Some(ProbeTargetOptions {
                resolver: nxdomain,
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = run_probe(&spec, "agent:t").await;
        assert_eq!(r.status, "fail");
        assert!(r.error_message.contains("NXDOMAIN"), "{}", r.error_message);
    }
}
