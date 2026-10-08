//! TCP port probe: dial the port spec, read greeting banners, elicit HTTP
//! banners on web ports, emit port_open/port_closed/banner evidence
//! (Go probe/ports.go + probe/banners.go semantics: ≤100 concurrent dials,
//! one retry on transient dial timeout, banner cut at first newline and
//! trimmed of \r\n\x00).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

const MAX_CONCURRENT_DIALS: usize = 100;
const BANNER_READ_TIMEOUT: Duration = Duration::from_secs(3);
/// No-greeting web ports get an active "GET / HTTP/1.0" elicit
/// (Go banners.go elicitPorts).
const ELICIT_PORTS: [u16; 12] = [80, 8080, 8000, 8008, 8443, 8081, 8888, 9000, 4848, 631, 9200, 5984];

pub struct TcpPortsProbe;

probe_impl!(TcpPortsProbe, "active:tcp", |ip: IpAddr, hint: &ProbeHint| async move {

        let mut out = Vec::new();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DIALS));
        let mut handles = Vec::new();
        for port in hint.port_spec.iter().copied() {
            let permit = sem.clone().acquire_owned().await.unwrap();
            handles.push((port, tokio::spawn(dial_and_banner(ip, port, hint.timeout)), permit));
        }
        for (port, h, _permit) in handles {
            if let Ok(Some(result)) = h.await {
                match result {
                    DialResult::Open { banner } => {
                        let mut e = ev("active:tcp", "port_open", ip, 1.0);
                        e.port = port as i64;
                        e.protocol = "tcp".into();
                        out.push(e);
                        if let Some(b) = banner {
                            let mut b_ev = ev("active:tcp", "banner", ip, 0.9);
                            b_ev.port = port as i64;
                            b_ev.protocol = "tcp".into();
                            b_ev.raw_data = Some(BTreeMap::from([("banner".into(), b)]));
                            out.push(b_ev);
                        }
                    }
                    DialResult::Refused => {
                        // RST-closed ports justify service-row deletion (#256)
                        let mut e = ev("active:tcp", "port_closed", ip, 1.0);
                        e.port = port as i64;
                        out.push(e);
                    }
                }
            }
        }
        // evidence order: dials complete out of order; Go emits per-dial as
        // they finish too, but classification order stability needs the
        // spec order — sort by (port, kind) with port_open before banner.
        out.sort_by_key(|e| (e.port, if e.kind == "port_open" { 0 } else { 1 }));
        let _ = port_name_note();
        out
});

fn port_name_note() {}

/// None = timeout/other; Some(Ok(stream)) = connected; Some(Err(is_refused)).
async fn try_connect(addr: SocketAddr, timeout: Duration) -> Option<Result<TcpStream, bool>> {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(s) => Some(s.map_err(|e| is_refused(&e))),
        Err(_) => None,
    }
}

enum DialResult {
    Open { banner: Option<String> },
    Refused,
}

async fn dial_and_banner(ip: IpAddr, port: u16, timeout: Duration) -> Option<DialResult> {
    let addr = SocketAddr::new(ip, port);
    // transient (timeout) dials get exactly one retry; refusals are final.
    let mut stream = match try_connect(addr, timeout).await {
        Some(Ok(s)) => s,
        Some(Err(refused)) if refused => return Some(DialResult::Refused),
        _ => match try_connect(addr, timeout).await {
            Some(Ok(s)) => s,
            Some(Err(refused)) if refused => return Some(DialResult::Refused),
            _ => return None,
        },
    };
    let _ = stream.set_nodelay(true);
    // greeting banner window
    let mut buf = [0u8; 512];
    let mut banner: Option<String> = None;
    if let Ok(Ok(n)) = tokio::time::timeout(BANNER_READ_TIMEOUT, stream.read(&mut buf)).await {
        if n > 0 {
            banner = Some(clean_banner(&buf[..n]));
        }
    }
    if banner.is_none() && ELICIT_PORTS.contains(&port) {
        // active elicit: GET / HTTP/1.0 (a fresh stream: the greeting read
        // consumed the socket)
        if let Ok(Ok(mut s2)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            if s2.write_all(b"GET / HTTP/1.0\r\n\r\n").await.is_ok() {
                if let Ok(Ok(n)) =
                    tokio::time::timeout(BANNER_READ_TIMEOUT, s2.read(&mut buf)).await
                {
                    if n > 0 {
                        banner = Some(clean_banner(&buf[..n]));
                    }
                }
            }
        }
    }
    Some(DialResult::Open { banner })
}

/// Active banner elicitation on web ports: GET / HTTP/1.0, read the first
/// response bytes, cut at newline (Go banners.go).
pub(crate) async fn elicit_http_banner(addr: SocketAddr) -> Option<String> {
    let mut s = TcpStream::connect(addr).await.ok()?;
    s.write_all(b"GET / HTTP/1.0

").await.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(BANNER_READ_TIMEOUT, s.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    Some(clean_banner(&buf[..n]))
}

/// Go: cut at first
fn clean_banner(raw: &[u8]) -> String {
    let cut = raw.iter().position(|b| *b == b'\n').map(|i| i).unwrap_or(raw.len());
    let s = String::from_utf8_lossy(&raw[..cut]);
    s.trim_matches(|c| c == '\r' || c == '\n' || c == '\0').to_string()
}

fn is_refused(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_cleaning() {
        assert_eq!(clean_banner(b"SSH-2.0-OpenSSH_9.6\r\nextra\x00junk"), "SSH-2.0-OpenSSH_9.6");
        assert_eq!(clean_banner(b"220 ok\r\n"), "220 ok");
        assert_eq!(clean_banner(b"\r\n\x00"), "");
    }

    #[tokio::test]
    async fn open_refused_and_banner_evidence() {
        // listener that greets like SSH
        let greet = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = greet.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = greet.accept().await {
                let _ = s.write_all(b"SSH-2.0-dropbear_2022\r\nbinary\x00").await;
            }
        });
        // silent listener (no greeting, non-HTTP port => no banner)
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p2 = silent.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = silent.accept().await;
        });
        // web port with an HTTP response (elicited banner)
        let web = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p3 = web.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = web.accept().await {
                let mut b = [0u8; 128];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n").await;
            }
        });

        let hint = ProbeHint {
            community_override: None,
            timeout: Duration::from_secs(2),
            community: "public".into(),
            port_spec: vec![p1, p2, p3],
            snmp_port: 161,
            rdns_servers: vec![],
            oui: std::sync::Arc::new(crate::engine::oui::Oui::parse("")),
            snmp_v3: None,
        };
        let out = TcpPortsProbe.probe("127.0.0.1".parse().unwrap(), &hint).await;
        let kinds: Vec<(i64, &str)> = out.iter().map(|e| (e.port, e.kind.as_str())).collect();
        assert!(kinds.contains(&(p1 as i64, "port_open")));
        assert!(kinds.contains(&(p2 as i64, "port_open")));
        assert!(kinds.contains(&(p3 as i64, "port_open")));
        let banner = out
            .iter()
            .find(|e| e.kind == "banner" && e.port == p1 as i64)
            .expect("SSH greeting banner");
        assert_eq!(banner.raw_data.as_ref().unwrap()["banner"], "SSH-2.0-dropbear_2022");
        // elicitation fires only on the fixed web-port list; verify the
        // helper directly against the ephemeral web listener.
        let elicited =
            elicit_http_banner(std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), p3)).await;
        assert!(elicited.unwrap().starts_with("HTTP/1.0 200"));
        // a closed port reports port_closed (bind-then-drop listener)
        let gone = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gone_port = gone.local_addr().unwrap().port();
        drop(gone);
        // small race window for the OS to actually close it
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let hint2 = ProbeHint { port_spec: vec![gone_port], ..hint };
        let out2 = TcpPortsProbe.probe("127.0.0.1".parse().unwrap(), &hint2).await;
        // Windows may silently drop loopback dials to closed ports instead
        // of RST; the hard guarantee is never port_open.
        assert!(
            !out2.iter().any(|e| e.kind == "port_open"),
            "closed port must not open: {out2:?}"
        );

    }

    #[test]
    fn refused_error_mapping() {
        use std::io::{Error, ErrorKind};
        assert!(is_refused(&Error::from(ErrorKind::ConnectionRefused)));
        assert!(is_refused(&Error::from(ErrorKind::ConnectionReset)));
        assert!(!is_refused(&Error::from(ErrorKind::TimedOut)));
        assert!(!is_refused(&Error::from(ErrorKind::PermissionDenied)));
    }
}
