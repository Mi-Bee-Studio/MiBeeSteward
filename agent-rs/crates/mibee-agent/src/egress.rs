//! Agent-side egress collector (#718): runs the center-pushed echo-source
//! round on the pushed cadence and reports raw outcomes — origin-ASN
//! enrichment stays on the center (one Cymru cache for every vantage).
//!
//! Sources: HTTP echo bodies (plain IPv4 or cdn-cgi/trace `ip=` lines), STUN
//! XOR-MAPPED-ADDRESS (UDP path shape under CGNAT), and the authoritative-
//! resolver DNS TXT echo. The local layer reads /proc/net/route (zero
//! permissions, little-endian hex gateway column).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::center::CenterClient;
use crate::wire::{now_rfc3339, EgressLocalReport, EgressPlanCommand, EgressResultReport, EgressRoundReport, EgressSourceSpec};

const TICK: Duration = Duration::from_secs(10);
/// Failed-report park queue bound (batches, oldest dropped first).
const PENDING_MAX: usize = 100;
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// HTTP echo timeout (Go center collector parity).
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);
/// STUN: one attempt's wait; the well-known packet loss gets a second try.
const STUN_TIMEOUT: Duration = Duration::from_secs(4);
/// DNS TXT echo round-trip.
const DNS_TIMEOUT: Duration = Duration::from_secs(6);

pub struct EgressRunner {
    fingerprint: String,
    sources: Vec<EgressSourceSpec>,
    interval_secs: i64,
    next_due_ms: i64,
}

impl EgressRunner {
    pub fn new() -> Self {
        EgressRunner { fingerprint: String::new(), sources: Vec::new(), interval_secs: 0, next_due_ms: 0 }
    }

    /// Apply a pushed plan (fingerprint-guarded; empty sources stop rounds).
    /// A fresh plan runs its first round immediately — the agent was idle
    /// until now, no stagger needed at one round per interval.
    pub fn apply_plan(&mut self, fingerprint: &str, sources: Vec<EgressSourceSpec>, interval_seconds: i64) {
        if fingerprint == self.fingerprint {
            return;
        }
        self.fingerprint = fingerprint.to_string();
        self.sources = sources;
        self.interval_secs = interval_seconds;
        self.next_due_ms = 0;
    }

    /// One tick: run a round when due. Returns the report to post (empty
    /// vec = nothing due or plan disabled).
    pub async fn tick(&mut self) -> Vec<EgressRoundReport> {
        if self.sources.is_empty() {
            return Vec::new();
        }
        let now = now_ms();
        if now < self.next_due_ms {
            return Vec::new();
        }
        let interval = if self.interval_secs > 0 { self.interval_secs } else { 300 };
        self.next_due_ms = now + interval * 1000;
        vec![run_round(&self.sources).await]
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl Default for EgressRunner {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One round: local default-route view + every source concurrently.
pub async fn run_round(sources: &[EgressSourceSpec]) -> EgressRoundReport {
    let round_at = now_rfc3339();
    let (gateway_ip, iface) = read_local_egress();
    let mac = iface_mac(&iface);
    let local = EgressLocalReport {
        iface,
        gateway_ip: gateway_ip.clone(),
        gateway_mac: mac,
    };
    let jobs: Vec<&EgressSourceSpec> = sources.iter().collect();
    let outcomes = futures::future::join_all(jobs.into_iter().map(|src| async move {
        let started = std::time::Instant::now();
        let (ip, err) = match src.kind.as_str() {
            "http" => http_echo(&src.target).await,
            "stun" => stun_echo(&src.target, STUN_TIMEOUT).await,
            "dns" => dns_echo(&src.target).await,
            other => (String::new(), format!("unknown kind {other:?}")),
        };
        EgressResultReport {
            source: src.name.clone(),
            kind: src.kind.clone(),
            ok: !ip.is_empty(),
            ms: (started.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
            ip,
            err,
        }
    }))
    .await;
    EgressRoundReport { round_at, local, results: outcomes }
}

/// Fetch a URL and extract the first public IPv4 in the body; cdn-cgi/trace
/// `ip=` lines win when present (Go collector parity).
async fn http_echo(url: &str) -> (String, String) {
    crate::tls_provider::ensure_tls_provider();
    let client = match reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(crate::prober::PROBE_USER_AGENT)
        .build()
    {
        Ok(c) => c,
        Err(e) => return (String::new(), e.to_string()),
    };
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => return (String::new(), trim_err(&e.to_string())),
    };
    let code = resp.status().as_u16();
    if code >= 400 {
        return (String::new(), format!("http status {code}"));
    }
    let body = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return (String::new(), trim_err(&e.to_string())),
    };
    let body = &body[..body.len().min(8192)];
    for line in String::from_utf8_lossy(body).lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "ip" {
                let ip = v.trim();
                if is_public_ip(ip) {
                    return (ip.to_string(), String::new());
                }
            }
        }
    }
    if let Some(ip) = first_ipv4(&String::from_utf8_lossy(body)) {
        if is_public_ip(&ip) {
            return (ip, String::new());
        }
    }
    (String::new(), "no public IPv4 in body".to_string())
}

/// RFC 5389 binding request → XOR-MAPPED-ADDRESS (or legacy MAPPED), two
/// attempts against the well-known packet loss.
async fn stun_echo(server: &str, timeout: Duration) -> (String, String) {
    let addr: std::net::SocketAddr = match server.parse() {
        Ok(a) => a,
        Err(_) => match tokio::net::lookup_host(server).await {
            Ok(mut it) => it.next().unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            Err(e) => return (String::new(), trim_err(&e.to_string())),
        },
    };
    let sock = match tokio::net::UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await {
        Ok(s) => s,
        Err(e) => return (String::new(), trim_err(&e.to_string())),
    };
    if let Err(e) = sock.connect(addr).await {
        return (String::new(), trim_err(&e.to_string()));
    }
    let mut req = [0u8; 20];
    req[0] = 0;
    req[1] = 1; // BINDING_REQUEST
    req[2] = 0;
    req[3] = 0;
    req[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut req[8..20]);
    let mut buf = vec![0u8; 1024];
    for _ in 0..2 {
        if let Err(e) = sock.send(&req).await {
            return (String::new(), trim_err(&e.to_string()));
        }
        match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Some(ip) = parse_stun_mapped_address(&buf[..n]) {
                    return (ip, String::new());
                }
            }
            _ => continue,
        }
    }
    (String::new(), "no mapped address in stun response".to_string())
}

/// parseStunMappedAddress parity: XOR-MAPPED-ADDRESS (0x0020/0x8020, RFC
/// 5389) with the magic-cookie XOR, or the legacy MAPPED-ADDRESS (0x0001).
pub fn parse_stun_mapped_address(msg: &[u8]) -> Option<String> {
    if msg.len() < 20 {
        return None;
    }
    let ml = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let mut attrs = &msg[20..];
    if ml < attrs.len() {
        attrs = &attrs[..ml];
    }
    let mut plain = None;
    while attrs.len() >= 4 {
        let typ = u16::from_be_bytes([attrs[0], attrs[1]]);
        let l = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attrs.len() < 4 + l {
            break;
        }
        let v = &attrs[4..4 + l];
        if (typ == 0x0020 || typ == 0x8020) && l >= 8 && v[1] == 0x01 {
            let x = u32::from_be_bytes([v[4], v[5], v[6], v[7]]) ^ 0x2112_A442;
            return Some(format!("{}.{}.{}.{}", x >> 24, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF));
        }
        if typ == 0x0001 && l >= 8 && v[1] == 0x01 && plain.is_none() {
            plain = Some(format!("{}.{}.{}.{}", v[4], v[5], v[6], v[7]));
        }
        let mut adv = 4 + l;
        if l % 4 != 0 {
            adv += 4 - l % 4;
        }
        if adv > attrs.len() {
            break;
        }
        attrs = &attrs[adv..];
    }
    plain
}

/// Ask "server|qname" for the qname's TXT records and return the first
/// public IPv4 found (the authoritative-resolver echo trick).
async fn dns_echo(target: &str) -> (String, String) {
    let Some((server, qname)) = target.split_once('|') else {
        return (String::new(), "dns source target must be server|qname".to_string());
    };
    let addr = match parse_resolver(server) {
        Ok(a) => a,
        Err(e) => return (String::new(), e),
    };
    let msg = match crate::engine::dns::udp_query(addr, qname, 16, DNS_TIMEOUT).await {
        Ok(m) => m,
        Err(e) => return (String::new(), trim_err(&e)),
    };
    for rr in &msg.answers {
        if let crate::engine::dns::RData::Txt(strs) = &rr.rdata {
            for s in strs {
                if let Some(ip) = first_ipv4(s) {
                    if is_public_ip(&ip) {
                        return (ip, String::new());
                    }
                }
            }
        }
    }
    (String::new(), "no public IPv4 in TXT".to_string())
}

/// resolver "host" | "host:port" → SocketAddr (53 implied).
fn parse_resolver(server: &str) -> Result<std::net::SocketAddr, String> {
    if let Ok(addr) = server.parse() {
        return Ok(addr);
    }
    if !server.contains(':') || server.starts_with('[') {
        return format!("{server}:53").parse().map_err(|e| format!("bad resolver: {e}"));
    }
    Err(format!("bad resolver {server:?}"))
}

/// First dotted-quad IPv4 in the text (word-bounded, 1-3 digit octets).
pub fn first_ipv4(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            let mut octets = 0;
            let mut ok = true;
            while octets < 4 {
                let mut digits = 0;
                while i < b.len() && b[i].is_ascii_digit() && digits < 3 {
                    i += 1;
                    digits += 1;
                }
                if digits == 0 {
                    ok = false;
                    break;
                }
                octets += 1;
                if octets < 4 {
                    if i < b.len() && b[i] == b'.' {
                        i += 1;
                    } else {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                let cand = &text[start..i];
                let after_ok = i >= b.len() || !(b[i].is_ascii_alphanumeric() || b[i] == b'.');
                let before_ok = start == 0 || !(b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'.');
                if after_ok && before_ok && cand.parse::<std::net::Ipv4Addr>().is_ok() {
                    return Some(cand.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Global-scope IPv4 check (Go isPublicIP parity): private/loopback/link-
/// local/multicast/unspecified/documentation/benchmark ranges are not egress
/// identities; CGNAT 100.64/10 deliberately IS (it is what the ISP presents).
pub fn is_public_ip(s: &str) -> bool {
    let Ok(ip) = s.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let o = ip.octets();
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    match o {
        [192, 0, _, _] => false,               // 192.0.0.0/24 + TEST-NET-1
        [198, 18..=19, _, _] => false,         // benchmarking
        [198, 51, 100, _] => false,            // TEST-NET-2
        [203, 0, 113, _] => false,             // TEST-NET-3
        _ => true,
    }
}

/// Default-route gateway + interface from /proc/net/route (little-endian
/// hex columns). Empty on non-Linux / missing file.
pub fn read_local_egress() -> (String, String) {
    match std::fs::read_to_string("/proc/net/route") {
        Ok(content) => parse_proc_net_route(&content),
        Err(_) => (String::new(), String::new()),
    }
}

/// parseProcNetRoute parity: the first default route's gateway + iface.
pub fn parse_proc_net_route(content: &str) -> (String, String) {
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 || cols[1] != "00000000" {
            continue;
        }
        let hex = cols[2];
        if hex.len() != 8 {
            continue;
        }
        let mut b = [0u8; 4];
        let mut ok = true;
        for i in 0..4 {
            match u8::from_str_radix(&hex[8 - 2 * i - 2..8 - 2 * i], 16) {
                Ok(v) => b[i] = v,
                Err(_) => ok = false,
            }
        }
        if ok {
            return (format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), cols[0].to_string());
        }
        return (String::new(), String::new());
    }
    (String::new(), String::new())
}

/// Best-effort interface MAC from /sys (forward-compat field; the center
/// does not persist it yet).
fn iface_mac(iface: &str) -> String {
    if iface.is_empty() {
        return String::new();
    }
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn trim_err(s: &str) -> String {
    s.chars().take(200).collect()
}

/// Background loop: tick the runner, post rounds with the #554 retry ladder
/// (4 attempts, exponential backoff), park failed batches bounded.
pub async fn run_egress(
    runner: Arc<Mutex<EgressRunner>>,
    client: Arc<CenterClient>,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    run_egress_with_tuning(runner, client, stop, RETRY_BACKOFF, TICK).await
}

/// Test surface: same loop with shrunken cadences.
pub async fn run_egress_with_tuning(
    runner: Arc<Mutex<EgressRunner>>,
    client: Arc<CenterClient>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    retry_backoff: Duration,
    tick: Duration,
) {
    let mut pending: Vec<Vec<EgressRoundReport>> = Vec::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick) => {}
            _ = stop.changed() => {
                let tail = runner.lock().await.tick().await;
                if !tail.is_empty() {
                    let _ = post_ladder(&client, &tail, retry_backoff).await;
                }
                return;
            }
        }
        // One parked batch per tick, oldest first.
        if !pending.is_empty() {
            let head = pending.remove(0);
            if post_ladder(&client, &head, retry_backoff).await.is_err() {
                pending.insert(0, head);
                continue;
            }
        }
        let rounds = runner.lock().await.tick().await;
        if rounds.is_empty() {
            continue;
        }
        if post_ladder(&client, &rounds, retry_backoff).await.is_err() {
            pending.push(rounds);
            while pending.len() > PENDING_MAX {
                pending.remove(0);
            }
            eprintln!("egress: round parked (center unreachable), pending={}", pending.len());
        }
    }
}

async fn post_ladder(
    client: &CenterClient,
    rounds: &[EgressRoundReport],
    base: Duration,
) -> Result<(), String> {
    let mut backoff = base;
    for attempt in 0..4 {
        match client.post_egress_rounds(rounds).await {
            Ok(_) => return Ok(()),
            Err(e) if attempt == 3 => return Err(e.0),
            Err(e) => {
                eprintln!("egress: post attempt {} failed: {}", attempt + 1, e.0);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    unreachable!("loop returns on the 4th attempt")
}

/// Apply a pushed egress plan (main.rs command dispatch helper).
pub async fn apply_pushed_plan(runner: &Arc<Mutex<EgressRunner>>, plan: EgressPlanCommand) -> String {
    let mut r = runner.lock().await;
    let n = plan.sources.len();
    r.apply_plan(&plan.fingerprint, plan.sources, plan.interval_seconds);
    format!(r#"{{"applied":"{}","sources":{n}}}"#, r.fingerprint())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_xor_and_plain_parse() {
        // XOR-MAPPED-ADDRESS: attr 0x0020, family 1, port 12345, xor'd addr.
        let mut msg = vec![0u8; 20];
        msg[0] = 1;
        let cookie = 0x2112A442u32;
        let mapped: u32 = u32::from_be_bytes([93, 184, 216, 34]);
        let x = mapped ^ cookie;
        let mut attr = Vec::new();
        attr.extend_from_slice(&0x0020u16.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0);
        attr.push(1);
        attr.extend_from_slice(&12345u16.to_be_bytes());
        attr.extend_from_slice(&x.to_be_bytes());
        msg.extend_from_slice(&attr);
        msg[2..4].copy_from_slice(&12u16.to_be_bytes()); // message length = attr bytes
        assert_eq!(parse_stun_mapped_address(&msg).as_deref(), Some("93.184.216.34"));

        // Legacy MAPPED-ADDRESS (plain).
        let mut msg2 = vec![0u8; 20];
        msg2[0] = 1;
        let mut attr2 = Vec::new();
        attr2.extend_from_slice(&0x0001u16.to_be_bytes());
        attr2.extend_from_slice(&8u16.to_be_bytes());
        attr2.push(0);
        attr2.push(1);
        attr2.extend_from_slice(&443u16.to_be_bytes());
        attr2.extend_from_slice(&[1, 2, 3, 4]);
        msg2.extend_from_slice(&attr2);
        msg2[2..4].copy_from_slice(&12u16.to_be_bytes());
        assert_eq!(parse_stun_mapped_address(&msg2).as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn proc_net_route_gateway_little_endian() {
        let content = "Iface\tDestination\tGateway\t\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                       end0\t00000000\t0102A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        let (gw, iface) = parse_proc_net_route(content);
        assert_eq!(gw, "192.168.2.1");
        assert_eq!(iface, "end0");
        // No default route → empty.
        let (gw2, _) = parse_proc_net_route("end0\t0102A8C0\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0\n");
        assert_eq!(gw2, "");
    }

    #[test]
    fn public_ip_classification() {
        for ok in ["93.184.216.34", "100.64.1.2" /* CGNAT counts */, "1.1.1.1"] {
            assert!(is_public_ip(ok), "{ok} should be public");
        }
        for bad in [
            "192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1", "169.254.1.1",
            "224.0.0.1", "0.0.0.0", "192.0.2.1", "198.51.100.1", "203.0.113.9",
            "198.18.0.1", "not-an-ip",
        ] {
            assert!(!is_public_ip(bad), "{bad} should not be public");
        }
    }

    #[test]
    fn first_ipv4_word_boundaries() {
        assert_eq!(first_ipv4("ip is 93.184.216.34 ok").as_deref(), Some("93.184.216.34"));
        assert_eq!(first_ipv4("ip=93.184.216.34\n").as_deref(), Some("93.184.216.34"));
        // Embedded in alphanumerics or longer dotted runs: not a match.
        assert_eq!(first_ipv4("a93.184.216.34b"), None);
        assert_eq!(first_ipv4("1.2.3.4.5"), None);
        assert_eq!(first_ipv4("999.1.1.1 hello"), None);
        assert_eq!(first_ipv4("no digits here"), None);
    }

    #[tokio::test]
    async fn egress_plan_apply_dedup_and_clear() {
        let mut r = EgressRunner::new();
        r.apply_plan("f1", vec![EgressSourceSpec { name: "a".into(), kind: "http".into(), target: "http://127.0.0.1:1/x".into() }], 60);
        assert_eq!(r.sources.len(), 1);
        // Same fingerprint: no-op even if the payload differs (center contract).
        r.apply_plan("f1", vec![], 30);
        assert_eq!(r.sources.len(), 1);
        assert_eq!(r.interval_secs, 60);
        // New fingerprint with empty sources clears.
        r.apply_plan("f2", vec![], 30);
        assert!(r.sources.is_empty());
        assert!(r.tick().await.is_empty(), "cleared plan runs nothing");
    }

    #[tokio::test]
    async fn egress_plan_tick_cadence() {
        let mut r = EgressRunner::new();
        // A source that always fails fast keeps the round offline-safe.
        r.apply_plan("f1", vec![EgressSourceSpec { name: "bad".into(), kind: "xyz".into(), target: String::new() }], 60);
        let first = r.tick().await;
        assert_eq!(first.len(), 1, "first round runs immediately");
        // Not due again within the interval.
        assert!(r.tick().await.is_empty());
    }

    /// One full round against local fakes: an HTTP echo body, a STUN
    /// responder with a fixed XOR-MAPPED-ADDRESS, a DNS TXT echo, and two
    /// broken specs — every source kind offline.
    #[tokio::test]
    async fn run_round_local_fakes() {
        // HTTP echo: answers the IP in the body.
        let tl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_target = format!("http://127.0.0.1:{}/ip", tl.local_addr().unwrap().port());
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = tl.accept().await {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let body = "93.184.216.34";
                let _ = s.write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes(),
                ).await;
            }
        });

        // STUN: answers every binding request with a fixed XOR-MAPPED-ADDRESS.
        let stun_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_target = stun_sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = stun_sock.recv_from(&mut buf).await else { return };
                if n < 20 { continue; }
                let mapped = u32::from_be_bytes([93, 184, 216, 99]) ^ 0x2112_A442;
                let mut resp = Vec::with_capacity(32);
                resp.extend_from_slice(&0x0101u16.to_be_bytes());
                resp.extend_from_slice(&12u16.to_be_bytes());
                resp.extend_from_slice(&buf[4..20]); // cookie + txn echoed
                resp.extend_from_slice(&0x0020u16.to_be_bytes());
                resp.extend_from_slice(&8u16.to_be_bytes());
                resp.push(0);
                resp.push(1); // IPv4
                resp.extend_from_slice(&443u16.to_be_bytes());
                resp.extend_from_slice(&mapped.to_be_bytes());
                let _ = stun_sock.send_to(&resp, from).await;
            }
        });

        // DNS TXT echo: answer the copied question with one TXT string.
        let dns_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_server = dns_sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = dns_sock.recv_from(&mut buf).await else { return };
                if n < 12 { continue; }
                let q = buf[..n].to_vec();
                let mut i = 12;
                while i < q.len() && q[i] != 0 { i += 1 + q[i] as usize; }
                i += 5; // root + qtype + qclass
                let txt = "93.184.216.100";
                let mut resp = q[..i].to_vec();
                resp[2] |= 0x80; // QR
                resp[3] = 0x80; // RD + RA
                resp[6..8].copy_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&[0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 60]);
                resp.extend_from_slice(&(txt.len() as u16 + 1).to_be_bytes());
                resp.push(txt.len() as u8);
                resp.extend_from_slice(txt.as_bytes());
                let _ = dns_sock.send_to(&resp, from).await;
            }
        });

        let report = run_round(&[
            EgressSourceSpec { name: "http-test".into(), kind: "http".into(), target: http_target },
            EgressSourceSpec { name: "stun-test".into(), kind: "stun".into(), target: stun_target },
            EgressSourceSpec { name: "dns-test".into(), kind: "dns".into(), target: format!("{dns_server}|echo.example") },
            EgressSourceSpec { name: "bad-kind".into(), kind: "xyz".into(), target: String::new() },
            EgressSourceSpec { name: "bad-dns".into(), kind: "dns".into(), target: "no-pipe".into() },
        ])
        .await;

        let by: std::collections::HashMap<&str, &EgressResultReport> =
            report.results.iter().map(|r| (r.source.as_str(), r)).collect();
        let http = by["http-test"];
        assert!(http.ok, "http err={}", http.err);
        assert_eq!(http.ip, "93.184.216.34");
        let stun = by["stun-test"];
        assert!(stun.ok, "stun err={}", stun.err);
        assert_eq!(stun.ip, "93.184.216.99");
        let dns = by["dns-test"];
        assert!(dns.ok, "dns err={}", dns.err);
        assert_eq!(dns.ip, "93.184.216.100");
        assert!(!by["bad-kind"].ok);
        assert!(by["bad-kind"].err.contains("unknown kind"));
        assert!(!by["bad-dns"].ok);
        assert!(by["bad-dns"].err.contains("server|qname"));
        // The local layer rides along (on Linux both fields resolve).
        assert!(!report.round_at.is_empty());
    }

    #[test]
    fn resolver_parsing() {
        assert!(parse_resolver("1.2.3.4").is_ok());
        assert_eq!(parse_resolver("1.2.3.4").unwrap().port(), 53);
        assert_eq!(parse_resolver("1.2.3.4:5353").unwrap().port(), 5353);
        assert!(parse_resolver("[::1]").is_ok());
        assert!(parse_resolver("bad host!").is_err());
    }

    #[test]
    fn local_egress_reads_proc() {
        let (gw, iface) = read_local_egress();
        // On a Linux test host the default route exists; on other platforms
        // both are empty. Never one-sided.
        assert_eq!(gw.is_empty(), iface.is_empty(), "gw={gw} iface={iface}");
    }
}
