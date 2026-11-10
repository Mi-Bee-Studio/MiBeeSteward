//! Vantage prober: applies center-pushed probe plans locally (10s tick;
//! targets due on a deterministic first-stagger then every interval), batches
//! results (10s or 32 rows), and parks-not-drops failed batches (bounded
//! oldest-first queue + retry ladder, the reporter's #554 pattern).

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::center::CenterClient;
use crate::wire::{
    PathSampleReport, ProbeResultReport, ProbeTargetOptions, ProbeTargetSpec, TracePlan,
};

/// Product probe UA (Go probe.UserAgent() parity, #713): several echo and
/// business endpoints answer 403/501 to unknown clients.
pub(crate) const PROBE_USER_AGENT: &str = concat!(
    "MiBeeSteward-probe/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Mi-Bee-Studio/MiBeeSteward)"
);

const TICK: Duration = Duration::from_secs(10); // schedule + flush cadence
const BATCH_MAX: usize = 32;
/// Failed-report park queue bound (batches, oldest dropped first) — mirrors
/// the reporter's pending cap.
const PENDING_MAX: usize = 100;
/// Base retry backoff for one batch (1s→2s→4s→8s ladder, 4 attempts).
const RETRY_BACKOFF: Duration = Duration::from_secs(1);
/// HTTP keyword inspection bound (matches the center's 1 MiB body limit).
const BODY_LIMIT: usize = 1 << 20;
/// Path traces bound: #719's failure snapshots are rate-limited to one per
/// target per 10 minutes so a hard-down site cannot tracebroom the box.
const FAIL_TRACE_COOLDOWN_MS: i64 = 10 * 60 * 1000;
/// Concurrent traces (center default parity).
const TRACE_CONCURRENCY: usize = 2;
/// User-Agent for http probes, the same product token the center sends
pub struct Prober {
    plan_fingerprint: String,
    targets: Vec<ProbeTargetSpec>,
    /// target id -> next-due unix ms (absent + fresh = run immediately).
    due: std::collections::HashMap<i64, i64>,
    vantage: String,
    /// Trace lane (#719): the pushed schedule, per-target next-due, and the
    /// failure-snapshot cooldown bookkeeping.
    trace: Option<TracePlan>,
    trace_due: std::collections::HashMap<i64, i64>,
    fail_flagged: std::collections::HashSet<i64>,
    last_fail_trace: std::collections::HashMap<i64, i64>,
}

impl Prober {
    pub fn new(vantage: String) -> Self {
        Prober {
            plan_fingerprint: String::new(),
            targets: Vec::new(),
            due: std::collections::HashMap::new(),
            vantage,
            trace: None,
            trace_due: std::collections::HashMap::new(),
            fail_flagged: std::collections::HashSet::new(),
            last_fail_trace: std::collections::HashMap::new(),
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.plan_fingerprint
    }

    /// Apply a plan (fingerprint-guarded; an empty list clears the plan).
    /// Every target's first run is staggered deterministically over the
    /// first minute so a fresh plan (or a plan re-push after a fingerprint
    /// change) does not march in lockstep (#604 jitter). The trace block
    /// rides the same fingerprint: a new plan resets the trace schedule too.
    pub fn apply_plan(
        &mut self,
        fingerprint: &str,
        targets: Vec<ProbeTargetSpec>,
        trace: Option<TracePlan>,
    ) {
        if fingerprint == self.plan_fingerprint {
            return;
        }
        self.plan_fingerprint = fingerprint.to_string();
        self.targets = targets;
        self.due.clear();
        let now = now_ms();
        for t in &self.targets {
            let interval = if t.interval_seconds > 0 {
                t.interval_seconds
            } else {
                300
            };
            self.due.insert(t.id, now + stagger_ms(t.id, interval));
        }
        self.trace = trace.filter(|t| !t.categories.is_empty());
        self.trace_due.clear();
        self.fail_flagged.clear();
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
            let interval = if spec.interval_seconds > 0 {
                spec.interval_seconds
            } else {
                300
            };
            self.due.insert(spec.id, now + interval * 1000);
            out.push(run_probe(&spec, &self.vantage).await);
        }
        out
    }

    /// Trace-lane cfg (max_ttl, per_hop_ms) when tracing is enabled.
    pub fn trace_tuning(&self) -> Option<(i64, i64)> {
        self.trace.as_ref().map(|t| (t.max_ttl, t.per_hop_ms))
    }

    /// Take the trace-due specs (#719, called by the tracer loop): category
    /// filter + first-sight stagger + interval. Failure-flagged targets ride
    /// along with trigger="failure". Mirrors the center's traceDueTargets.
    pub fn trace_due_specs(&mut self, now: i64) -> Vec<(ProbeTargetSpec, &'static str)> {
        let Some(plan) = self.trace.clone() else {
            self.trace_due.clear();
            return Vec::new();
        };
        if plan.categories.is_empty() {
            self.trace_due.clear();
            return Vec::new();
        }
        let interval = if plan.interval_minutes > 0 {
            plan.interval_minutes
        } else {
            30
        } * 60_000;
        let mut jobs: Vec<(ProbeTargetSpec, &'static str)> = Vec::new();
        // Failure snapshots first: due now (cooldown was applied at flag
        // time); they ride the same due-map walk tagged trigger="failure".
        let flagged: std::collections::HashSet<i64> = self.fail_flagged.drain().collect();
        for id in &flagged {
            self.trace_due.insert(*id, now);
        }
        for t in self.targets.clone() {
            if !plan.categories.iter().any(|c| c == &t.category) {
                continue;
            }
            match self.trace_due.get(&t.id) {
                None => {
                    // First sight: stagger within the interval (restarts do
                    // not fire every trace at once) — Go parity.
                    let n = jobs.len() as i64 + 1;
                    self.trace_due
                        .insert(t.id, now + t.id.rem_euclid(n) * interval / 16);
                }
                Some(d) if now < *d => continue,
                Some(_) => {
                    self.trace_due.insert(t.id, now + interval);
                    let trigger = if flagged.contains(&t.id) {
                        "failure"
                    } else {
                        "baseline"
                    };
                    jobs.push((t, trigger));
                }
            }
        }
        jobs
    }

    /// Failure-trigger hook (#719): a just-failed probe schedules an
    /// immediate trace snapshot, one per cooldown window per target, only
    /// for targets the trace plan actually covers.
    pub fn note_probe_failure(&mut self, target_id: i64, now: i64) {
        let Some(plan) = &self.trace else { return };
        if plan.categories.is_empty() {
            return;
        }
        let Some(spec) = self.targets.iter().find(|t| t.id == target_id) else {
            return;
        };
        if !plan.categories.iter().any(|c| c == &spec.category) {
            return;
        }
        if let Some(last) = self.last_fail_trace.get(&target_id) {
            if now - *last < FAIL_TRACE_COOLDOWN_MS {
                return;
            }
        }
        self.last_fail_trace.insert(target_id, now);
        self.fail_flagged.insert(target_id);
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
        ProbeFailure {
            timeout: false,
            message: message.into(),
        }
    }
    fn timeout(message: impl Into<String>) -> Self {
        ProbeFailure {
            timeout: true,
            message: message.into(),
        }
    }
}

impl From<String> for ProbeFailure {
    fn from(message: String) -> Self {
        ProbeFailure {
            timeout: message.contains("timeout"),
            message,
        }
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
                    if o.expected_status.is_empty() {
                        None
                    } else {
                        Some(&o.expected_status)
                    }
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
                report.status = if e.contains("timeout") {
                    "timeout"
                } else {
                    "fail"
                }
                .into();
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
                report.status = if e.contains("timeout") {
                    "timeout"
                } else {
                    "fail"
                }
                .into();
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

/// Resolve host:port with retries, resilient to slow local resolvers.
///
/// The static-musl agent carries musl's resolver, whose retry budget is a
/// single ~5s window. On LANs fronted by a caching stub (systemd-resolved,
/// dnsmasq+smartdns) a momentarily slow upstream makes getaddrinfo give up
/// with EAI_AGAIN while glibc/Go clients on the same box sail through —
/// field-observed as intermittent ~5007ms "error sending request" failures
/// on every dual-name business target. Retrying the whole lookup a few
/// times absorbs exactly that transient.
///
/// Generic over the resolve future so tests can drive fail-fail-succeed
/// sequences without touching the real resolver.
async fn resolve_retry_core<F, Fut>(
    attempts: u32,
    delay: Duration,
    mut resolve: F,
) -> Result<Vec<std::net::SocketAddr>, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>>,
{
    let mut last = String::new();
    for attempt in 0..attempts.max(1) {
        match resolve().await {
            Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
            Ok(_) => last = "empty answer".to_string(),
            Err(e) => last = e.to_string(),
        }
        if attempt + 1 < attempts {
            tokio::time::sleep(delay).await;
        }
    }
    Err(last)
}

/// Resilient host resolution for the http executor: getaddrinfo (musl)
/// retried up to `attempts` times with a short pause between rounds.
async fn resolve_host_resilient(
    host: &str,
    port: u16,
    attempts: u32,
    delay: Duration,
) -> Result<Vec<std::net::SocketAddr>, String> {
    resolve_retry_core(attempts, delay, || {
        let host = host.to_string();
        async move {
            tokio::task::spawn_blocking(move || {
                (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|it| it.collect::<Vec<_>>())
            })
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
        }
    })
    .await
}

async fn http_probe(
    target: &str,
    opts: Option<&ProbeTargetOptions>,
    timeout: Duration,
) -> Result<(u16, Option<Vec<u8>>), ProbeFailure> {
    let url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("http://{target}")
    };
    crate::tls_provider::ensure_tls_provider();
    // TLS posture (#604): verify by default, center parity; the explicit
    // per-target opt-out is the only way to accept a broken cert.
    let ignore_tls = opts.map(|o| o.ignore_tls_errors).unwrap_or(false);
    let is_head = opts.map(|o| o.method.as_str()).unwrap_or("") == "HEAD";
    let method = if is_head {
        reqwest::Method::HEAD
    } else {
        reqwest::Method::GET
    };

    // Resolve OUTSIDE reqwest (retry loop above) and pin the answer with
    // resolve_to_addrs: reqwest's own single-shot resolution inherits the
    // musl budget and reports only a truncated "error sending request".
    // Pinning keeps SNI/Host on the URL hostname while connecting straight
    // to the resolved addresses.
    let parsed = reqwest::Url::parse(&url)
        .map_err(|e| ProbeFailure::other(format!("bad url {url:?}: {e}")))?;
    let host = parsed.host_str().unwrap_or_default().to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addrs = resolve_host_resilient(&host, port, 3, Duration::from_millis(300))
        .await
        .map_err(ProbeFailure::other)?;

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(PROBE_USER_AGENT)
        .danger_accept_invalid_certs(ignore_tls)
        .resolve_to_addrs(&host, &addrs)
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
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ProbeFailure::other(e.to_string()))?
        {
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
            if o.record.is_empty() {
                "A".to_string()
            } else {
                o.record.clone()
            },
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
            Some(s) => s
                .parse()
                .map_err(|e| format!("bad system nameserver: {e}"))?,
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
        let hit = expected_ips
            .iter()
            .any(|w| got.iter().any(|g| g.eq_ignore_ascii_case(w)));
        if !hit {
            return Err(format!(
                "resolved {got:?} does not intersect expected_ips {expected_ips:?}"
            ));
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
        return format!("{resolver}:53")
            .parse()
            .map_err(|e| format!("bad resolver: {e}"));
    }
    if resolver.starts_with('[') {
        return format!("{resolver}:53")
            .parse()
            .map_err(|e| format!("bad resolver: {e}"));
    }
    Err(format!("bad resolver {resolver:?}"))
}

/// Shared payload matcher for http keyword and tcp expect (#605, Go
/// matchPayload parity). Err carries e.g. an invalid regex.
fn match_payload(mode: &str, pattern: &str, payload: &[u8]) -> Result<bool, String> {
    match mode {
        "" | "contains" => Ok(payload
            .windows(pattern.len().max(1))
            .any(|w| w == pattern.as_bytes())),
        "not_contains" => Ok(!payload
            .windows(pattern.len().max(1))
            .any(|w| w == pattern.as_bytes())),
        "regex" => {
            let re =
                regex::bytes::Regex::new(pattern).map_err(|e| format!("invalid regex: {e}"))?;
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
    let t = target
        .trim_start_matches("https://")
        .trim_start_matches("http://");
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
                if !reports.is_empty() {
                    // Failure-trigger hook (#719): a failed probe flags an
                    // immediate trace snapshot (the tracer loop picks it up).
                    let mut p = prober.lock().await;
                    let now = now_ms();
                    for r in &reports {
                        if r.status != "success" {
                            p.note_probe_failure(r.target_id, now);
                        }
                    }
                }
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
            if post_with_retry(&client, &head, retry_backoff)
                .await
                .is_err()
            {
                pending.insert(0, head);
            }
            continue;
        }

        if batch.len() >= BATCH_MAX || (last_flush.elapsed() >= tick && !batch.is_empty()) {
            if post_with_retry(&client, &batch, retry_backoff)
                .await
                .is_err()
            {
                pending.push(std::mem::take(&mut batch));
                while pending.len() > PENDING_MAX {
                    pending.remove(0);
                }
                eprintln!(
                    "prober: batch parked (center unreachable), pending={}",
                    pending.len()
                );
            } else {
                batch.clear();
            }
            last_flush = Instant::now();
        }
    }
}

/// Tracer loop (#719): drains the trace schedule every tick, runs due
/// traces bounded to TRACE_CONCURRENCY, posts batches with the #554 ladder
/// and parks failures (bounded, oldest-first). Idles at zero cost when the
/// plan carries no trace block.
pub async fn run_tracer(
    prober: Arc<tokio::sync::Mutex<Prober>>,
    client: Arc<CenterClient>,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    run_tracer_with_tuning(prober, client, stop, RETRY_BACKOFF, TICK).await
}

/// Test surface: same loop with shrunken cadences.
pub async fn run_tracer_with_tuning(
    prober: Arc<tokio::sync::Mutex<Prober>>,
    client: Arc<CenterClient>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    retry_backoff: Duration,
    tick: Duration,
) {
    let mut pending: Vec<Vec<PathSampleReport>> = Vec::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick) => {}
            _ = stop.changed() => {
                // Parked batches stay parked across a stop (bounded memory,
                // retried after restart), same as the prober.
                return;
            }
        }
        // One parked batch per tick, oldest first.
        if !pending.is_empty() {
            let head = pending.remove(0);
            if post_paths(&client, &head, retry_backoff).await.is_err() {
                pending.insert(0, head);
                continue;
            }
        }
        let (specs, tuning) = {
            let mut p = prober.lock().await;
            (p.trace_due_specs(now_ms()), p.trace_tuning())
        };
        let Some((max_ttl, per_hop_ms)) = tuning else {
            continue;
        };
        if specs.is_empty() {
            continue;
        }
        let tracer = Arc::new(crate::tracer::Tracer::new(max_ttl, per_hop_ms));
        // Chunked bounded concurrency: TRACE_CONCURRENCY traces in flight,
        // no per-task semaphore bookkeeping (cadence is minutes, not micro).
        let mut reports: Vec<PathSampleReport> = Vec::with_capacity(specs.len());
        for chunk in specs.chunks(TRACE_CONCURRENCY) {
            let futs = chunk.iter().map(|(spec, trigger)| {
                let tracer = Arc::clone(&tracer);
                let spec = spec.clone();
                let trigger: &str = trigger;
                async move { crate::tracer::trace_spec(&tracer, &spec, trigger).await }
            });
            reports.extend(futures::future::join_all(futs).await);
        }
        if post_paths(&client, &reports, retry_backoff).await.is_err() {
            pending.push(reports);
            while pending.len() > PENDING_MAX {
                pending.remove(0);
            }
            eprintln!(
                "tracer: batch parked (center unreachable), pending={}",
                pending.len()
            );
        }
    }
}

/// Path-batch posting ladder (mirror of post_with_retry).
async fn post_paths(
    client: &CenterClient,
    batch: &[PathSampleReport],
    base_backoff: Duration,
) -> Result<(), String> {
    let mut backoff = base_backoff;
    for attempt in 0..4 {
        match client.post_path_reports(batch).await {
            Ok(_) => return Ok(()),
            Err(e) if attempt == 3 => return Err(e.0),
            Err(e) => {
                eprintln!("tracer: post attempt {} failed: {}", attempt + 1, e.0);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    unreachable!("loop returns on the 4th attempt")
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
        p.apply_plan(
            "f1",
            vec![ProbeTargetSpec {
                id: 1,
                module: "http".into(),
                target: "127.0.0.1:1".into(),
                interval_seconds: 3600,
                ..Default::default()
            }],
            None,
        );
        assert_eq!(p.targets.len(), 1);
        let before = p.due.clone();
        p.apply_plan("f1", vec![], None); // same fingerprint: no-op
        assert_eq!(p.targets.len(), 1);
        assert_eq!(p.due, before);
        p.apply_plan("f2", vec![], None); // new fingerprint clears the plan
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
        p.apply_plan(
            "f1",
            vec![ProbeTargetSpec {
                id: 33,
                module: "http".into(),
                target: "127.0.0.1:1".into(),
                interval_seconds: 3600,
                ..Default::default()
            }],
            None,
        );
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
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let (code, body) = http_probe(&format!("127.0.0.1:{port}"), None, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(code, 204);
        assert!(body.is_none());
    }

    /// #713 parity: http probes carry the center's product User-Agent. The
    /// responder answers 501 unless it sees it (the www.qq.com behaviour).
    #[tokio::test]
    async fn http_probe_sends_product_user_agent() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 1024];
                let n = s.read(&mut b).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&b[..n]).to_ascii_lowercase();
                let reply: &[u8] = if req.contains("\r\nuser-agent: mibeesteward-probe/") {
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
                } else {
                    b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n"
                };
                let _ = s.write_all(reply).await;
            }
        });
        let (code, _) = http_probe(&format!("127.0.0.1:{port}"), None, Duration::from_secs(2)).await.unwrap();
        assert_eq!(code, 204, "probe must send the MiBeeSteward-probe User-Agent");
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
                let _ = s
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                            .as_bytes(),
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
            options: opts(ProbeTargetOptions {
                keyword: "unhealthy".into(),
                ..Default::default()
            }),
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
                let _ = s
                    .write_all(
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
        assert!(
            r.latency_ms >= 100.0,
            "latency_ms {} too small",
            r.latency_ms
        );
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
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
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
        assert!(
            r.error_message.contains("expected_ips"),
            "{}",
            r.error_message
        );

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

    #[tokio::test]
    async fn resolve_retry_absorbs_transient_failures() {
        // The field shape: getaddrinfo gives up twice (slow stub upstream),
        // the third round answers. The retry loop must absorb exactly that.
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let want = vec!["127.0.0.1:80".parse::<std::net::SocketAddr>().unwrap()];
        let addrs = want.clone();
        let result = resolve_retry_core(3, Duration::from_millis(1), || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let addrs = addrs.clone();
            async move {
                if n < 2 {
                    Err(std::io::Error::other("Try again"))
                } else {
                    Ok(addrs)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), want);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn resolve_retry_reports_last_error_after_budget() {
        // Persistent resolver failure exhausts the budget and surfaces the
        // LAST error (better diagnostics than the old truncated reqwest
        // "error sending request").
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let err = resolve_retry_core(3, Duration::from_millis(1), || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(std::io::Error::other(format!("attempt {n} failed"))) }
        })
        .await
        .unwrap_err();
        assert!(
            err.contains("attempt 2 failed"),
            "last error should survive: {err}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn resolve_retry_treats_empty_answer_as_failure() {
        // A resolver answering with zero records must not be mistaken for
        // success (connecting to nothing would surface as an opaque error).
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = AtomicU32::new(0);
        let err = resolve_retry_core(2, Duration::from_millis(1), || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(vec![]) }
        })
        .await
        .unwrap_err();
        assert_eq!(err, "empty answer");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn resolve_host_resilient_resolves_loopback() {
        // End-to-end through the real getaddrinfo path (no DNS needed):
        // a literal IP host resolves on the first attempt.
        let addrs = resolve_host_resilient("127.0.0.1", 80, 3, Duration::from_millis(1))
            .await
            .unwrap();
        assert!(addrs.iter().any(|a| a.port() == 80));
    }

    fn trace_spec(id: i64, category: &str) -> ProbeTargetSpec {
        ProbeTargetSpec {
            id,
            module: "http".into(),
            target: format!("http://t{id}.example/"),
            interval_seconds: 3600,
            category: category.into(),
            ..Default::default()
        }
    }

    /// No trace block → the lane is inert (tuning None, no due specs).
    #[test]
    fn trace_lane_disabled_without_plan() {
        let mut p = Prober::new("agent:x".into());
        p.apply_plan("f1", vec![trace_spec(1, "external")], None);
        assert!(p.trace_tuning().is_none());
        assert!(p.trace_due_specs(now_ms()).is_empty());
        // Empty-categories trace plans also disable (defense vs bad pushes).
        p.apply_plan(
            "f2",
            vec![trace_spec(1, "external")],
            Some(TracePlan {
                categories: vec![],
                interval_minutes: 5,
                max_ttl: 8,
                per_hop_ms: 100,
            }),
        );
        assert!(p.trace_tuning().is_none());
    }

    /// Category filter + first-sight stagger + interval reschedule.
    #[test]
    fn trace_lane_category_filter_and_cadence() {
        let mut p = Prober::new("agent:x".into());
        p.apply_plan(
            "f1",
            vec![
                trace_spec(1, "external"),
                trace_spec(2, "lan"),
                trace_spec(3, "quality"),
            ],
            Some(TracePlan {
                categories: vec!["external".into(), "quality".into()],
                interval_minutes: 30,
                max_ttl: 20,
                per_hop_ms: 400,
            }),
        );
        assert_eq!(p.trace_tuning(), Some((20, 400)));
        let now = now_ms();
        // First sight: everything only seeds (stagger offsets may be 0, the
        // seed call itself returns nothing).
        assert!(p.trace_due_specs(now).is_empty(), "first sight only seeds");
        // lan (id 2) never joins; both covered categories fire (0 offsets).
        let jobs = p.trace_due_specs(now);
        let ids: Vec<i64> = jobs.iter().map(|(s, _)| s.id).collect();
        assert_eq!(ids, vec![1, 3]);
        assert!(jobs.iter().all(|(_, t)| *t == "baseline"));
        // Rescheduled a full interval out.
        assert!(p.trace_due_specs(now + 29 * 60_000).is_empty());
        assert_eq!(p.trace_due_specs(now + 31 * 60_000).len(), 2);
    }

    /// Failure snapshots (#719): fire immediately, carry trigger=failure,
    /// respect the per-target cooldown, and ignore out-of-category targets.
    #[test]
    fn trace_lane_failure_hook() {
        let mut p = Prober::new("agent:x".into());
        p.apply_plan(
            "f1",
            vec![trace_spec(5, "external"), trace_spec(6, "lan")],
            Some(TracePlan {
                categories: vec!["external".into()],
                interval_minutes: 30,
                max_ttl: 20,
                per_hop_ms: 400,
            }),
        );
        let now = now_ms();
        p.note_probe_failure(5, now);
        p.note_probe_failure(6, now); // lan: not covered by the plan
                                      // The flagged target rides the FIRST due walk with trigger=failure.
        let jobs = p.trace_due_specs(now);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0.id, 5);
        assert_eq!(jobs[0].1, "failure");
        // Cooldown: a second failure within 10 minutes flags nothing.
        p.note_probe_failure(5, now + 60_000);
        assert!(
            p.trace_due_specs(now + 60_000).is_empty(),
            "cooldown suppresses"
        );
        // Past the cooldown a fresh failure snapshots again.
        p.note_probe_failure(5, now + 11 * 60_000);
        let jobs = p.trace_due_specs(now + 11 * 60_000);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].1, "failure");
        // Disabled lane: the hook is a no-op.
        let mut q = Prober::new("agent:x".into());
        q.apply_plan("f1", vec![trace_spec(5, "external")], None);
        q.note_probe_failure(5, now);
        assert!(q.trace_due_specs(now).is_empty());
    }
}
