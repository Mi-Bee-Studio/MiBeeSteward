//! Center client: the six agent→center endpoints with Go's exact retry
//! semantics, plus the Reporter (buffered batches + heartbeat + bounded
//! pending queue).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::wire::{now_rfc3339, AgentCommand, AgentReport, CommandComplete, ProbeResultReport, ReportAck};

/// Transport-level outcome of a POST /agents/report attempt.
#[derive(Debug)]
pub enum PostOutcome {
    Accepted(ReportAck),
    /// 4xx except 429: unrecoverable — the batch is dropped (Go treats it as
    /// delivered so it never re-queues).
    Rejected(u16),
}

#[derive(Debug)]
pub struct TransportError(pub String);

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct CenterClient {
    base: String,
    token: String,
    pub http: reqwest::Client,
}

impl CenterClient {
    pub fn new(base: String, token: String, timeout: Duration) -> Self {
        // provider must be installed before reqwest builds its rustls config
        crate::tls_provider::ensure_tls_provider();
        CenterClient {
            base: base.trim_end_matches('/').to_string(),
            token,
            // Aggressive idle-conn reaping so a restarted center doesn't
            // strand half-open conns (Go httpclient.go rationale).
            http: reqwest::Client::builder()
                .timeout(timeout)
                .pool_idle_timeout(Duration::from_secs(10))
                .pool_max_idle_per_host(10)
                .connect_timeout(Duration::from_secs(5))
                .build()
                .expect("center http client"),
        }
    }

    fn bearer(&self) -> reqwest::header::HeaderValue {
        let mut v = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.token))
            .expect("token is header-safe");
        v.set_sensitive(true);
        v
    }

    /// POST /api/v1/agents/report. `state_hash` goes in X-Network-State-Hash
    /// (scan batches only — never passive batches, never pending retries).
    pub async fn post_report(
        &self,
        report: &AgentReport,
        state_hash: Option<&str>,
    ) -> Result<PostOutcome, TransportError> {
        let mut req = self
            .http
            .post(format!("{}/api/v1/agents/report", self.base))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .json(report);
        if let Some(h) = state_hash {
            req = req.header("X-Network-State-Hash", h);
        }
        let resp = req.send().await.map_err(|e| TransportError(e.to_string()))?;
        let status = resp.status().as_u16();
        match status {
            s if (200..300).contains(&s) => {
                let ack: ReportAck = resp.json().await.map_err(|e| TransportError(e.to_string()))?;
                Ok(PostOutcome::Accepted(ack))
            }
            // 4xx except 429: terminal (429 falls through as retriable).
            400 | 401 | 403 | 409 => Ok(PostOutcome::Rejected(status)),
            s => Err(TransportError(format!("report POST status {s}"))),
        }
    }

    /// GET /api/v1/agents/commands (bare JSON array).
    pub async fn get_commands(&self) -> Result<Vec<AgentCommand>, TransportError> {
        let resp = self
            .http
            .get(format!("{}/api/v1/agents/commands", self.base))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        if resp.status().as_u16() != 200 {
            return Err(TransportError(format!("commands GET status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| TransportError(format!("commands decode: {e}")))
    }

    /// POST /commands/{id}/ack — before execution; response ignored (Go).
    pub async fn ack_command(&self, id: i64) -> Result<(), TransportError> {
        self.http
            .post(format!("{}/api/v1/agents/commands/{id}/ack", self.base))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        Ok(())
    }

    /// POST /commands/{id}/complete — fire-and-forget.
    pub async fn complete_command(
        &self,
        id: i64,
        status: &str,
        result: &str,
    ) -> Result<(), TransportError> {
        self.http
            .post(format!("{}/api/v1/agents/commands/{id}/complete", self.base))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&CommandComplete { status: status.to_string(), result: result.to_string() })
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        Ok(())
    }

    /// POST /api/v1/agents/probe-report — batch of results.
    pub async fn post_probe_results(&self, results: &[ProbeResultReport]) -> Result<i64, TransportError> {
        let resp = self
            .http
            .post(format!("{}/api/v1/agents/probe-report", self.base))
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .json(&serde_json::json!({ "results": results }))
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(TransportError(format!("probe-report status {status}")));
        }
        #[derive(serde::Deserialize)]
        struct Ack {
            accepted: i64,
        }
        let ack: Ack = resp.json().await.map_err(|e| TransportError(e.to_string()))?;
        Ok(ack.accepted)
    }

    /// GET /api/v1/agents/fingerprints?rev= — 204 not-modified, 200 tar.gz +
    /// X-Fingerprint-Rev, 503 unavailable.
    pub async fn get_fingerprints(&self, rev: &str) -> Result<FingerprintFetch, TransportError> {
        let resp = self
            .http
            .get(format!("{}/api/v1/agents/fingerprints", self.base))
            .query(&[("rev", rev)])
            .header(reqwest::header::AUTHORIZATION, self.bearer())
            .timeout(Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        match resp.status().as_u16() {
            204 => Ok(FingerprintFetch::NotModified),
            200 => {
                let rev = resp
                    .headers()
                    .get("X-Fingerprint-Rev")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| TransportError(e.to_string()))?
                    .to_vec();
                match rev {
                    Some(rev) => Ok(FingerprintFetch::Tarball { rev, bytes }),
                    None => Err(TransportError("fingerprint 200 without X-Fingerprint-Rev".into())),
                }
            }
            503 => Ok(FingerprintFetch::Unavailable),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(TransportError(format!(
                    "fingerprints GET status {s}: {}",
                    body.chars().take(200).collect::<String>()
                )))
            }
        }
    }
}

#[derive(Debug)]
pub enum FingerprintFetch {
    NotModified,
    Tarball { rev: String, bytes: Vec<u8> },
    Unavailable,
}

/// Injected clock so tests drive cadence deterministically.
pub trait Clock: Send + Sync {
    fn now_unix_ms(&self) -> i64;
}
pub struct RealClock;
impl Clock for RealClock {
    fn now_unix_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// Buffered scan-report reporter with heartbeat, retry/backoff and a
/// bounded pending queue (Go internal/agent/reporter.go semantics).
pub struct Reporter {
    client: Arc<CenterClient>,
    agent_id: String,
    network_cidr: String,
    max_buf: usize,
    state: Mutex<ReporterState>,
    clock: Arc<dyn Clock>,
    retry_backoff: Duration,
    // MIPS32 lacks 64-bit lock-free atomics: the epoch start is kept as
    // seconds (u32) and re-multiplied on read.
    process_start_sec: AtomicU32,
    pub scans_total: AtomicU32,
    pub meta: std::sync::Mutex<crate::wire::AgentMeta>,
}

struct ReporterState {
    buffer: Vec<crate::wire::ReportedHost>,
    passive: bool,
    pending: Vec<AgentReport>, // oldest-first, cap 100 drop-oldest
    last_post_ms: i64,
}

impl Reporter {
    pub fn new(
        client: Arc<CenterClient>,
        agent_id: String,
        network_cidr: String,
        max_buf: usize,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let now = clock.now_unix_ms();
        Reporter {
            client,
            agent_id,
            network_cidr,
            max_buf,
            clock,
            state: Mutex::new(ReporterState {
                buffer: Vec::new(),
                passive: false,
                pending: Vec::new(),
                last_post_ms: 0,
            }),
            retry_backoff: Duration::from_secs(1),
            process_start_sec: AtomicU32::new((now / 1000) as u32),
            scans_total: AtomicU32::new(0),
            meta: std::sync::Mutex::new(crate::wire::AgentMeta::default()),
        }
    }

    /// Buffer alive hosts from a scan; early flush at max_buf.
    pub async fn report(&self, hosts: Vec<crate::wire::ReportedHost>) {
        self.scans_total.fetch_add(1, Ordering::Relaxed);
        let mut st = self.state.lock().await;
        st.buffer.extend(hosts);
        if st.buffer.len() >= self.max_buf {
            let batch = std::mem::take(&mut st.buffer);
            let passive = std::mem::take(&mut st.passive);
            drop(st);
            self.flush(batch, passive).await;
        }
    }

    /// Buffer a single passive-origin host (origin:"passive", no state hash).
    pub async fn report_passive(&self, host: crate::wire::ReportedHost) {
        let mut st = self.state.lock().await;
        st.buffer.push(host);
        st.passive = true;
    }

    /// One flush tick: drain ONE pending retry (no state hash), then the
    /// current buffer (with hash unless passive), else heartbeat when idle
    /// and >=30s since any successful POST.
    pub async fn tick(&self) {
        {
            let mut st = self.state.lock().await;
            if !st.pending.is_empty() {
                let batch = st.pending.remove(0);
                drop(st);
                self.post_with_retry(batch, None).await;
            }
        }
        let mut st = self.state.lock().await;
        if !st.buffer.is_empty() {
            let batch = std::mem::take(&mut st.buffer);
            let passive = std::mem::take(&mut st.passive);
            drop(st);
            self.flush(batch, passive).await;
            return;
        }
        let now = self.clock.now_unix_ms();
        if now - st.last_post_ms < 30_000 {
            return;
        }
        drop(st);
        self.flush(Vec::new(), false).await;
    }

    /// Override the retry backoff base (tests use milliseconds; production
    /// keeps Go's 1s -> 2s -> 4s -> 8s ladder).
    pub fn set_retry_backoff(&mut self, base: Duration) {
        self.retry_backoff = base;
    }

    /// Pending-queue depth (test observability).
    pub async fn pending_len(&self) -> usize {
        self.state.lock().await.pending.len()
    }

    /// Total successful POSTs observable via last-post timestamp bump
    /// (test helper).
    pub async fn last_post_ms(&self) -> i64 {
        self.state.lock().await.last_post_ms
    }

    /// Final flush on shutdown.
    pub async fn stop_flush(&self) {
        let mut st = self.state.lock().await;
        while !st.pending.is_empty() {
            let batch = st.pending.remove(0);
            drop(st);
            self.post_with_retry(batch, None).await;
            st = self.state.lock().await;
        }
        if !st.buffer.is_empty() {
            let batch = std::mem::take(&mut st.buffer);
            let passive = std::mem::take(&mut st.passive);
            drop(st);
            self.flush(batch, passive).await;
        }
    }

    async fn flush(&self, hosts: Vec<crate::wire::ReportedHost>, passive: bool) {
        let hash = if !passive && !hosts.is_empty() {
            Some(crate::wire::network_state_hash(&hosts))
        } else {
            None
        };
        let report = AgentReport {
            agent_id: self.agent_id.clone(),
            network_name: String::new(),
            network_cidr: self.network_cidr.clone(),
            scanned_at: now_rfc3339(),
            meta: Some(self.build_meta()),
            hosts: if hosts.is_empty() { None } else { Some(hosts) },
            origin: if passive { "passive".to_string() } else { String::new() },
        };
        self.post_with_retry(report, hash.as_deref()).await;
    }

    /// 4 attempts, 1s/2s/4s/8s backoff; 4xx-except-429 terminal (dropped,
    /// treated as delivered); exhaustion parks the batch in the pending
    /// queue (cap 100, drop-oldest).
    async fn post_with_retry(&self, report: AgentReport, hash: Option<&str>) -> bool {
        let mut backoff = self.retry_backoff;
        for _ in 0..4 {
            match self.client.post_report(&report, hash).await {
                Ok(PostOutcome::Accepted(_)) => {
                    self.state.lock().await.last_post_ms = self.clock.now_unix_ms();
                    return true;
                }
                Ok(PostOutcome::Rejected(status)) => {
                    eprintln!("reporter: center rejected report (terminal, status {status})");
                    self.state.lock().await.last_post_ms = self.clock.now_unix_ms();
                    return true;
                }
                Err(e) => {
                    eprintln!("reporter: post attempt failed: {}", e.0);
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
            }
        }
        let mut st = self.state.lock().await;
        st.pending.push(report);
        while st.pending.len() > 100 {
            st.pending.remove(0);
        }
        false
    }

    fn build_meta(&self) -> crate::wire::AgentMeta {
        let mut meta = self.meta.lock().unwrap().clone();
        let now = self.clock.now_unix_ms();
        let start = i64::from(self.process_start_sec.load(Ordering::Relaxed)) * 1000;
        meta.uptime_sec = ((now - start) / 1000).max(0);
        meta.scans_total = i64::from(self.scans_total.load(Ordering::Relaxed));
        meta
    }
}
