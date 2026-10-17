//! Six-endpoint contract tests against a minimal in-process mock center.
//! Pins the Go wire behavior: auth header, state-hash header rules, report
//! retry/terminal semantics, command double-encoded payloads + ack-before-
//! execute, probe batch shape, fingerprint rev negotiation.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mibee_agent::center::{CenterClient, Clock, FingerprintFetch, PostOutcome, RealClock, Reporter};
use mibee_agent::wire::{AgentCommand, AgentReport, ProbeResultReport, ReportedHost};

/// Steppable clock: 401-cooldown tests advance it deterministically.
struct MockClock(AtomicI64);
impl MockClock {
    fn at(ms: i64) -> Self {
        MockClock(AtomicI64::new(ms))
    }
    fn advance_ms(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}
impl Clock for MockClock {
    fn now_unix_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

// ---------- tiny HTTP mock ----------

#[derive(Clone, Debug)]
struct RecordedReq {
    method: String,
    path: String,
    query: String,
    auth: String,
    state_hash: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct MockCenter {
    log: Arc<Mutex<Vec<RecordedReq>>>,
    script: Arc<Mutex<Vec<MockAction>>>, // consumed per matching request
    // Shared with the serving task so tests can flip the center's posture
    // (e.g. 401 -> 200, "token restored") after spawn.
    default: Arc<Mutex<MockAction>>,
}

#[derive(Clone)]
enum MockAction {
    Json(u16, String),
    Gzip(u16, String, Vec<u8>),
}

impl MockCenter {
    fn new() -> Self {
        MockCenter {
            log: Arc::new(Mutex::new(Vec::new())),
            script: Arc::new(Mutex::new(Vec::new())),
            default: Arc::new(Mutex::new(MockAction::Json(200, r#"{"accepted":1}"#.into()))),
        }
    }

    fn then(&self, action: MockAction) -> &Self {
        self.script.lock().unwrap().push(action);
        self
    }

    fn set_default(&self, action: MockAction) {
        *self.default.lock().unwrap() = action;
    }

    async fn serve(self, listener: tokio::net::TcpListener) {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let mock = self.clone();
            tokio::spawn(async move {
                loop {
                    let Some(req) = read_request(&mut sock).await else { return };
                    let action = {
                        let mut script = mock.script.lock().unwrap();
                        if script.is_empty() { mock.default.lock().unwrap().clone() } else { script.remove(0) }
                    };
                    mock.log.lock().unwrap().push(req.clone());
                    let (head, body) = match &action {
                        MockAction::Json(status, body) => (
                            format!(
                                "HTTP/1.1 {} \r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                status_line(*status),
                                body.len()
                            ),
                            body.as_bytes().to_vec(),
                        ),
                        MockAction::Gzip(status, rev, bytes) => (
                            format!(
                                "HTTP/1.1 {} \r\nContent-Type: application/gzip\r\nContent-Length: {}\r\nX-Fingerprint-Rev: {}\r\nConnection: close\r\n\r\n",
                                status_line(*status),
                                bytes.len(),
                                rev
                            ),
                            bytes.clone(),
                        ),
                    };
                    let mut out = head.into_bytes();
                    out.extend_from_slice(&body);
                    use tokio::io::AsyncWriteExt;
                    if sock.write_all(&out).await.is_err() {
                        return;
                    }
                }
            });
        }
    }
}

fn status_line(status: u16) -> String {
    match status {
        200 => "200 OK".into(),
        204 => "204 No Content".into(),
        400 => "400 Bad Request".into(),
        401 => "401 Unauthorized".into(),
        403 => "403 Forbidden".into(),
        409 => "409 Conflict".into(),
        429 => "429 Too Many Requests".into(),
        500 => "500 Internal Server Error".into(),
        503 => "503 Service Unavailable".into(),
        other => format!("{other} Status"),
    }
}

fn http_response(status: u16, ctype: &str, body: &[u8]) -> String {
    format!("HTTP/1.1 {} \r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_line(status), body.len())
}

async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<RecordedReq> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // read headers
    loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let content_len = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < pos + 4 + content_len {
                let n = sock.read(&mut chunk).await.ok()?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = buf[pos + 4..].to_vec();
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or_default().to_string();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let target = parts.next().unwrap_or_default().to_string();
            let (path, query) = match target.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (target.clone(), String::new()),
            };
            let auth = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .map(|l| l.split(':').nth(1).unwrap_or_default().trim().to_string())
                .unwrap_or_default();
            let state_hash = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("x-network-state-hash:"))
                .map(|l| l.split(':').nth(1).unwrap_or_default().trim().to_string());
            return Some(RecordedReq { method, path, query, auth, state_hash, body });
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn spawn_mock() -> (String, MockCenter) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mock = MockCenter::new();
    tokio::spawn(mock.clone().serve(listener));
    (format!("http://{addr}"), mock)
}

fn client(base: &str) -> Arc<CenterClient> {
    Arc::new(CenterClient::new(base.into(), "testtoken".into(), std::time::Duration::from_secs(5)))
}

fn host(ip: &str) -> ReportedHost {
    ReportedHost { ip: ip.into(), alive: true, ..Default::default() }
}

// ---------- tests ----------

#[tokio::test]
async fn report_posts_bearer_json_and_parses_ack() {
    let (base, mock) = spawn_mock().await;
    let c = client(&base);
    let report = AgentReport {
        agent_id: "lan-63".into(),
        network_cidr: "192.0.2.0/24".into(),
        scanned_at: "2026-10-05T01:00:00.000Z".into(),
        hosts: Some(vec![host("192.0.2.5")]),
        ..Default::default()
    };
    let out = c.post_report(&report, Some("deadbeef")).await.unwrap();
    match out {
        PostOutcome::Accepted(ack) => assert_eq!(ack.accepted, 1),
        other => panic!("expected Accepted, got {other:?}"),
    }
    let log = mock.log.lock().unwrap();
    let r = log.last().unwrap();
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/api/v1/agents/report");
    assert_eq!(r.auth, "Bearer testtoken");
    assert_eq!(r.state_hash.as_deref(), Some("deadbeef"));
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(body["agent_id"], "lan-63");
    assert_eq!(body["hosts"][0]["ip"], "192.0.2.5");
}

// ---------- 401 semantics (issue #554) ----------
//
// A 401 from the center means "token unknown right now" — which happens in
// legitimate ops (fresh-DB migration with a token-restore window, token
// rotation). The reporter must NOT treat it as terminal: batches are parked
// (data survives the gap), ticks go quiet for a cool-down window, and the
// first tick after the window re-delivers everything once the token returns.

const AUTH_COOLDOWN_MS: i64 = 5 * 60 * 1000;

#[tokio::test]
async fn auth_401_parks_batch_cools_down_then_self_heals() {
    let (base, mock) = spawn_mock().await;
    mock.set_default(MockAction::Json(401, "invalid agent token\n".into()));
    let c = client(&base);
    let clock = Arc::new(MockClock::at(1_800_000_000_000));
    let mut reporter =
        Reporter::new(c, "lan-63".into(), "192.0.2.0/24".into(), 256, clock.clone());
    reporter.set_auth_retry_backoff(Duration::from_millis(AUTH_COOLDOWN_MS as u64));

    reporter.report(vec![host("192.0.2.1")]).await;
    reporter.tick().await; // buffer flush -> 401 -> parked + cooldown
    assert_eq!(reporter.pending_len().await, 1, "401 must park the batch, not drop it");
    assert_eq!(mock.log.lock().unwrap().len(), 1);

    // Every tick inside the cooldown window is a no-op: no retries, no
    // heartbeats, no buffer flushes — even with new data waiting.
    reporter.report(vec![host("192.0.2.2")]).await;
    reporter.tick().await;
    assert_eq!(
        mock.log.lock().unwrap().len(),
        1,
        "cooldown suppresses all posts for the whole window"
    );

    // Token restored (center answers 200 again). Ticks BEFORE the window
    // expires still stay quiet; the first tick after it drains the parked
    // batch (pending-queue rule: no state hash) and then the buffer.
    mock.set_default(MockAction::Json(200, r#"{"accepted":1}"#.into()));
    clock.advance_ms(AUTH_COOLDOWN_MS - 1_000);
    reporter.tick().await;
    assert_eq!(mock.log.lock().unwrap().len(), 1, "still inside the cooldown");
    clock.advance_ms(2_000);
    reporter.tick().await;
    assert_eq!(reporter.pending_len().await, 0, "parked batch drains on recovery");
    {
        let log = mock.log.lock().unwrap();
        assert!(log.len() >= 3, "drain + buffer flush expected, got {}", log.len());
        assert!(log[1].state_hash.is_none(), "parked drain must not re-send the state hash");
        let drained: serde_json::Value = serde_json::from_slice(&log[1].body).unwrap();
        assert_eq!(
            drained["hosts"][0]["ip"], "192.0.2.1",
            "the host observed before the token gap must survive it"
        );
        let buffered: serde_json::Value = serde_json::from_slice(&log[2].body).unwrap();
        assert_eq!(buffered["hosts"][0]["ip"], "192.0.2.2");
    }

    // Recovery clears the cooldown: a fresh batch posts on the next tick
    // without waiting out another window.
    reporter.report(vec![host("192.0.2.9")]).await;
    reporter.tick().await;
    let log = mock.log.lock().unwrap();
    let last: serde_json::Value = serde_json::from_slice(&log.last().unwrap().body).unwrap();
    assert_eq!(last["hosts"][0]["ip"], "192.0.2.9");
}

#[tokio::test]
async fn auth_401_heartbeat_sets_cooldown_without_parking() {
    let (base, mock) = spawn_mock().await;
    mock.set_default(MockAction::Json(401, "invalid agent token\n".into()));
    let c = client(&base);
    let clock = Arc::new(MockClock::at(1_800_000_000_000));
    let mut reporter =
        Reporter::new(c, "lan-63".into(), "192.0.2.0/24".into(), 256, clock.clone());
    reporter.set_auth_retry_backoff(Duration::from_millis(AUTH_COOLDOWN_MS as u64));

    reporter.tick().await; // idle heartbeat -> 401 -> cooldown, nothing to park
    assert_eq!(reporter.pending_len().await, 0, "empty heartbeats carry no data; never parked");
    reporter.tick().await;
    assert_eq!(mock.log.lock().unwrap().len(), 1, "cooldown holds after a 401 heartbeat");
}

#[tokio::test]
async fn terminal_4xx_other_than_401_still_drops_immediately() {
    // 400/403/409 stay Go-parity terminal: dropped as delivered, no requeue,
    // and crucially NO cooldown — the next batch still posts right away.
    let (base, mock) = spawn_mock().await;
    mock.set_default(MockAction::Json(400, "bad request\n".into()));
    let c = client(&base);
    let reporter = Reporter::new(c, "lan-63".into(), "192.0.2.0/24".into(), 256, Arc::new(RealClock));
    reporter.report(vec![host("192.0.2.1")]).await;
    reporter.tick().await; // 400 -> terminal drop
    assert_eq!(reporter.pending_len().await, 0);
    assert_eq!(mock.log.lock().unwrap().len(), 1);
    reporter.report(vec![host("192.0.2.2")]).await;
    reporter.tick().await; // no cooldown: the next batch posts immediately
    assert_eq!(mock.log.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn stop_flush_is_bounded_when_center_keeps_401ing() {
    // Shutdown during a token gap: exactly one drain attempt, then give up
    // with the batch re-parked. The old loop could spin forever once a
    // 401-parked batch never left the queue (#554).
    let (base, mock) = spawn_mock().await;
    mock.set_default(MockAction::Json(401, "invalid agent token\n".into()));
    let c = client(&base);
    let clock = Arc::new(MockClock::at(1_800_000_000_000));
    let mut reporter =
        Reporter::new(c, "lan-63".into(), "192.0.2.0/24".into(), 256, clock);
    reporter.set_auth_retry_backoff(Duration::from_millis(AUTH_COOLDOWN_MS as u64));
    reporter.report(vec![host("192.0.2.1")]).await;
    reporter.tick().await; // 401 -> parked + cooldown
    let flushed = tokio::time::timeout(Duration::from_secs(5), reporter.stop_flush()).await;
    assert!(flushed.is_ok(), "stop_flush must terminate, not spin on the 401 park");
    assert_eq!(reporter.pending_len().await, 1, "batch stays parked for the next start");
    assert_eq!(mock.log.lock().unwrap().len(), 2, "one initial 401 + one shutdown drain attempt");
}

#[tokio::test]
async fn stop_flush_is_bounded_when_center_is_down() {
    // Transport-failure exhaustion also re-parks; shutdown must not retry
    // those rounds forever either.
    let (base, mock) = spawn_mock().await;
    mock.set_default(MockAction::Json(500, "boom".into()));
    let c = client(&base);
    let mut reporter = Reporter::new(c, "lan-63".into(), "192.0.2.0/24".into(), 256, Arc::new(RealClock));
    reporter.set_retry_backoff(Duration::from_millis(10));
    reporter.report(vec![host("192.0.2.1")]).await;
    reporter.tick().await; // 4 fast failures -> parked
    assert_eq!(reporter.pending_len().await, 1);
    let flushed = tokio::time::timeout(Duration::from_secs(5), reporter.stop_flush()).await;
    assert!(flushed.is_ok(), "stop_flush must terminate after one final retry round");
    let log = mock.log.lock().unwrap();
    assert_eq!(log.len(), 8, "4 attempts + 4 shutdown attempts, then bounded exit");
}

#[tokio::test]
async fn server_errors_retry_then_park_then_drain() {
    let (base, mock) = spawn_mock().await;
    // Attempts 1-4 see 500 (parked); the drain attempt sees 200.
    for _ in 0..4 {
        mock.then(MockAction::Json(500, "boom".into()));
    }
    mock.then(MockAction::Json(200, r#"{"accepted":3}"#.into()));
    mock.set_default(MockAction::Json(500, "boom".into()));
    let c = client(&base);
    let mut reporter = Reporter::new(Arc::clone(&c), "lan-63".into(), "192.0.2.0/24".into(), 256, Arc::new(RealClock));
    reporter.set_retry_backoff(std::time::Duration::from_millis(10));
    reporter.report(vec![host("192.0.2.1")]).await;
    reporter.tick().await; // 4 failed attempts (fast backoff) -> parked
    assert_eq!(reporter.pending_len().await, 1, "exhausted retries park the batch");
    // tick again: one drain attempt per tick; the scripted 200 accepts it
    reporter.tick().await;
    assert_eq!(reporter.pending_len().await, 0, "drain succeeds on the 200");
    let log = mock.log.lock().unwrap();
    // The original batch's attempts carry the hash (that's the initial
    // post); the DRAIN attempt (the last request, after the 200) must NOT
    // re-send it — Go rule for pending-queue retries.
    assert!(log.len() >= 5, "4 failed attempts + 1 drain, got {}", log.len());
    assert!(log[log.len() - 1].state_hash.is_none(), "drain re-sent the state hash");
}

#[tokio::test]
async fn heartbeat_has_null_hosts_and_no_state_hash() {
    let (base, mock) = spawn_mock().await;
    let c = client(&base);
    let reporter = Reporter::new(c.clone(), "lan-63".into(), "192.0.2.0/24".into(), 256, Arc::new(RealClock));
    reporter.tick().await; // empty buffer + never posted -> heartbeat
    let log = mock.log.lock().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
    assert!(body["hosts"].is_null(), "heartbeat hosts:null, got {}", body["hosts"]);
    assert!(log[0].state_hash.is_none());
    drop(log);
    // immediate second tick: throttled (<30s since last post)
    reporter.tick().await;
    assert_eq!(mock.log.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn passive_single_host_batch_has_origin_passive_no_hash() {
    let (base, mock) = spawn_mock().await;
    let c = client(&base);
    let reporter = Reporter::new(c, "lan-63".into(), "192.0.2.0/24".into(), 256, Arc::new(RealClock));
    reporter.report_passive(host("192.0.2.9")).await;
    reporter.tick().await;
    let log = mock.log.lock().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
    assert_eq!(body["origin"], "passive");
    assert!(log[0].state_hash.is_none());
}

#[tokio::test]
async fn commands_flow_ack_before_complete() {
    let (base, mock) = spawn_mock().await;
    // GET response first, then ack 204, complete 204
    mock.then(MockAction::Json(
        200,
        r#"[{"id":7,"agent_id":"agent-lan-63","command":"scan","payload":"{\"targets\":\"192.0.2.0/24\",\"timeout\":300}","status":"pending","created_at":"2026-10-05T08:00:00Z","acknowledged_at":null,"result":null}]"#.into(),
    ));
    let c = client(&base);
    let cmds: Vec<AgentCommand> = c.get_commands().await.unwrap();
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].command, "scan");
    let scan: mibee_agent::wire::ScanCommand = serde_json::from_str(&cmds[0].payload).unwrap();
    assert_eq!(scan.targets, "192.0.2.0/24");
    c.ack_command(7).await.unwrap();
    c.complete_command(7, "done", r#"{"run_id":1,"targets":"192.0.2.0/24"}"#).await.unwrap();
    let log = mock.log.lock().unwrap();
    let paths: Vec<&str> = log.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(paths, vec!["/api/v1/agents/commands", "/api/v1/agents/commands/7/ack", "/api/v1/agents/commands/7/complete"]);
    let complete_body: serde_json::Value = serde_json::from_slice(&log[2].body).unwrap();
    assert_eq!(complete_body["status"], "done");
    assert_eq!(complete_body["result"], r#"{"run_id":1,"targets":"192.0.2.0/24"}"#);
}

#[tokio::test]
async fn probe_report_batch_shape_and_ack() {
    let (base, mock) = spawn_mock().await;
    let c = client(&base);
    let results = vec![ProbeResultReport {
        target_id: 4,
        vantage: "agent:agent-lan-63".into(),
        status: "success".into(),
        latency_ms: 12.5,
        ..Default::default()
    }];
    // PostOutcome (#604): Accepted carries the ack, 4xx would be Rejected
    // (terminal — the park queue treats it as delivered).
    match c.post_probe_results(&results).await.unwrap() {
        mibee_agent::center::PostOutcome::Accepted(ack) => assert_eq!(ack.accepted, 1),
        other => panic!("expected Accepted, got {other:?}"),
    }
    let log = mock.log.lock().unwrap();
    assert_eq!(log[0].path, "/api/v1/agents/probe-report");
    let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
    assert_eq!(body["results"][0]["target_id"], 4);
    assert_eq!(body["results"][0]["latency_ms"], 12.5);
    assert_eq!(body["results"][0]["vantage"], "agent:agent-lan-63");
}

/// The prober park queue (#604): a center outage no longer drops batches —
/// they park (bounded) and flush once the center recovers.
#[tokio::test]
async fn probe_results_park_and_recover() {
    use mibee_agent::prober::{run_prober_with_tuning, Prober};
    use std::time::Duration;

    // A fast local responder as the probe target: each tick produces a
    // success row in milliseconds, keeping the loop's timing deterministic.
    let tl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("127.0.0.1:{}", tl.local_addr().unwrap().port());
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut s, _)) = tl.accept().await {
            let mut b = [0u8; 256];
            let _ = s.read(&mut b).await;
            let _ = s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
        }
    });

    let (base, mock) = spawn_mock().await;
    let c = client(&base);
    let prober = std::sync::Arc::new(tokio::sync::Mutex::new(Prober::new("agent:t".into())));
    // id 0 → stagger offset 0: the target is due on the first tick.
    prober.lock().await.apply_plan(
        "f1",
        vec![mibee_agent::wire::ProbeTargetSpec {
            id: 0,
            module: "http".into(),
            target,
            interval_seconds: 3600,
            timeout_seconds: 2,
            ..Default::default()
        }],
    );
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    // The first flush burns its whole 4-attempt ladder on 503 (retriable).
    mock.then(MockAction::Json(503, String::new()));
    mock.then(MockAction::Json(503, String::new()));
    mock.then(MockAction::Json(503, String::new()));
    mock.then(MockAction::Json(503, String::new()));
    // The mock's default is 200 {"accepted":1}: the parked batch drains on
    // the next tick's recovery slot.

    let task = tokio::spawn(run_prober_with_tuning(
        prober.clone(),
        c.clone(),
        stop_rx,
        Duration::from_millis(5),
        Duration::from_millis(50),
    ));
    // Ladder (4×503 + backoffs) parks the batch; the following tick drains
    // it against the recovered (default 200) center.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    stop_tx.send(true).unwrap();
    match task.await {
        Ok(()) => {}
        Err(e) => panic!("prober task failed: {e}"),
    }

    let log = mock.log.lock().unwrap();
    let probe_posts = log.iter().filter(|r| r.path.contains("probe-report")).count();
    assert_eq!(probe_posts, 5, "4 failed ladder attempts + 1 recovery drain");
}


#[tokio::test]
async fn fingerprint_rev_negotiation() {
    let (base, mock) = spawn_mock().await;
    let c = client(&base);
    // same rev -> 204
    mock.then(MockAction::Json(204, String::new()));
    match c.get_fingerprints("abc").await.unwrap() {
        FingerprintFetch::NotModified => {}
        other => panic!("expected NotModified, got {other:?}"),
    }
    // new rev -> 200 gzip + header
    let gz: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4];
    mock.then(MockAction::Gzip(200, "def567".into(), gz.clone()));
    match c.get_fingerprints("abc").await.unwrap() {
        FingerprintFetch::Tarball { rev, bytes } => {
            assert_eq!(rev, "def567");
            assert_eq!(bytes, gz);
        }
        other => panic!("expected Tarball, got {other:?}"),
    }
    // unavailable -> 503
    mock.then(MockAction::Json(503, "unavailable".into()));
    assert!(matches!(c.get_fingerprints("abc").await.unwrap(), FingerprintFetch::Unavailable));
    let log = mock.log.lock().unwrap();
    assert!(log[0].query.contains("rev=abc"), "rev query param: {}", log[0].query);
}

#[tokio::test]
async fn reporter_early_flush_at_buffer_cap() {
    let (base, mock) = spawn_mock().await;
    let c = client(&base);
    let reporter = Reporter::new(c, "lan-63".into(), "192.0.2.0/24".into(), 4, Arc::new(RealClock));
    reporter
        .report(vec![
            host("192.0.2.1"),
            host("192.0.2.2"),
            host("192.0.2.3"),
            host("192.0.2.4"),
        ])
        .await;
    // cap=4 reached -> immediate flush without tick
    let log = mock.log.lock().unwrap();
    assert_eq!(log.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
    assert_eq!(body["hosts"].as_array().unwrap().len(), 4);
    assert!(log[0].state_hash.is_some(), "scan batch carries state hash");
}
