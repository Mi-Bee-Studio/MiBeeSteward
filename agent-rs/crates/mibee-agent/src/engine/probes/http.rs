//! HTTP probe: GET / over plain HTTP on the fixed web port set, one
//! redirect allowed, <=64KB body, title case-insensitive + whitespace
//! collapsed + capped 200 chars; emits only when >=2 non-empty fields
//! (Go probe/http.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

const WEB_PORTS: [u16; 11] = [80, 8080, 8000, 8008, 8081, 8888, 9000, 9200, 5984, 631, 4848];
const MAX_BODY: usize = 64 * 1024;

pub struct HttpProbe;

probe_impl!(HttpProbe, "active:http", |ip: IpAddr, hint: &ProbeHint| async move { let mut out = Vec::new();
        for port in WEB_PORTS {
            if !hint.port_spec.contains(&port) {
                continue; // Go probes its fixed set regardless; but honoring
                          // a whitelist keeps custom specs authoritative.
            }
            let timeout = hint.timeout.min(Duration::from_secs(4));
            if let Some(fields) = fetch_http(ip, port, timeout, 1).await {
                if fields.len() >= 2 {
                    let mut e = ev("active:http", "http", ip, 0.9);
                    e.port = port as i64;
                    e.protocol = "tcp".into();
                    e.raw_data = Some(fields.into_iter().collect());
                    out.push(e);
                }
            }
        }
        out });

/// Minimal HTTP/1.1 GET with `redirects_left` hops. Returns raw_data fields
/// (status, server, powered_by, title, url, content_type) on any response.
pub async fn fetch_http(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    mut redirects_left: u32,
) -> Option<BTreeMap<String, String>> {
    let mut port = port;
    loop {
        match fetch_http_once(ip, port, timeout, &mut redirects_left).await? {
            HttpOutcome::Done(fields) => return Some(fields),
            HttpOutcome::Follow(next_port) => port = next_port,
        }
    }
}

enum HttpOutcome {
    Done(BTreeMap<String, String>),
    Follow(u16),
}

/// None = transport failure; Some(None) = follow one more redirect.
async fn fetch_http_once(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    redirects_left: &mut u32,
) -> Option<HttpOutcome> {
    let addr = SocketAddr::new(ip, port);
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: MiBee-Steward-scanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(timeout, s.read_to_end(&mut buf)).await.ok()?;
    if buf.len() > MAX_BODY + 8192 {
        buf.truncate(MAX_BODY + 8192);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let status_line = lines.next()?;
    let status: String = status_line.split_whitespace().nth(1)?.to_string();
    let mut server = String::new();
    let mut powered_by = String::new();
    let mut content_type = String::new();
    let mut location = String::new();
    for line in lines {
        let (k, v) = line.split_once(':')?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "server" => server = v.to_string(),
            "x-powered-by" => powered_by = v.to_string(),
            "content-type" => content_type = v.to_string(),
            "location" => location = v.to_string(),
            _ => {}
        }
    }
    if matches!(status.as_str(), "301" | "302" | "303" | "307" | "308") && !location.is_empty() {
        if *redirects_left > 0 {
            // same-host redirect only (absolute http://host:port/path or path)
            if let Some((rip, rport)) = parse_location(&location, ip, port) {
                if rip == ip && rport != port {
                    *redirects_left -= 1;
                    return Some(HttpOutcome::Follow(rport));
                }
                if rip == ip && rport == port {
                    // self-redirect: stop following
                }
            }
        }
    }
    let title = extract_title(body);
    let mut fields = BTreeMap::new();
    fields.insert("status".into(), status);
    if !server.is_empty() {
        fields.insert("server".into(), server);
    }
    if !powered_by.is_empty() {
        fields.insert("powered_by".into(), powered_by);
    }
    if !content_type.is_empty() {
        fields.insert("content_type".into(), content_type);
    }
    if !title.is_empty() {
        fields.insert("title".into(), title);
    }
    fields.insert("url".into(), format!("http://{ip}:{port}/"));
    Some(HttpOutcome::Done(fields))
}

fn parse_location(loc: &str, ip: IpAddr, port: u16) -> Option<(IpAddr, u16)> {
    if let Some(rest) = loc.strip_prefix("http://") {
        let hostport = rest.split('/').next()?;
        let (host, p) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().unwrap_or(80)),
            None => (hostport, 80),
        };
        let rip: IpAddr = host.parse().ok()?;
        Some((rip, p))
    } else {
        Some((ip, port))
    }
}

/// <title> extraction: case-insensitive tags, whitespace collapsed, cap 200.
pub fn extract_title(body: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let Some(start) = lower.find("<title") else { return String::new() };
    let after = &body[start..];
    let Some(gt) = after.find('>') else { return String::new() };
    let rest = &after[gt + 1..];
    let Some(endrel) = rest.to_ascii_lowercase().find("</title") else { return String::new() };
    let raw = &rest[..endrel];
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_extraction() {
        assert_eq!(extract_title("<html><TITLE>  MiWiFi   Router </TITLE></html>"), "MiWiFi Router");
        let long = "x".repeat(300);
        assert_eq!(extract_title(&format!("<title>{long}</title>")).len(), 200);
        assert_eq!(extract_title("no title here"), "");
    }

    #[tokio::test]
    async fn fetches_server_title_and_redirect() {
        let direct = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dp = direct.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = direct.accept().await {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx/1.24.0\r\n\r\n<html><title>  MiWiFi   Router </title></html>",
                    )
                    .await;
            }
        });
        let redirect = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (rp, target_port) = {
            let p = redirect.local_addr().unwrap().port();
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            (p, dp)
        };
        tokio::spawn(async move {
            while let Ok((mut s, _)) = redirect.accept().await {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target_port}/\r\n\r\n").as_bytes())
                    .await;
            }
        });
        let fields = fetch_http("127.0.0.1".parse().unwrap(), dp, Duration::from_secs(2), 1)
            .await
            .unwrap();
        assert_eq!(fields["status"], "200");
        assert_eq!(fields["server"], "nginx/1.24.0");
        assert_eq!(fields["title"], "MiWiFi Router");
        let fields = fetch_http("127.0.0.1".parse().unwrap(), rp, Duration::from_secs(2), 1)
            .await
            .unwrap();
        assert_eq!(fields["title"], "MiWiFi Router", "one redirect is followed");
    }
}
