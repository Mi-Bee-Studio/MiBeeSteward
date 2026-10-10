//! RTSP / ONVIF / /metrics probes (Go probe/protocol.go): fixed candidate
//! ports, small bodies, strict emission conditions.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

// ---------- RTSP ----------

pub struct RtspProbe;

probe_impl!(RtspProbe, "active:rtsp", |ip: IpAddr, hint: &ProbeHint| async move {

        let mut out = Vec::new();
        for port in [554u16, 8554] {
            let Some((status, server)) =
                rtsp_options(ip, port, hint.timeout).await else { continue };
            let mut e = ev("active:rtsp", "rtsp_banner", ip, 0.95);
            e.port = port as i64;
            e.protocol = "tcp".into();
            let mut rd = BTreeMap::new();
            rd.insert("status".into(), status);
            if !server.is_empty() {
                rd.insert("server".into(), server);
            }
            e.raw_data = Some(rd);
            out.push(e);
        }
        out
});

pub(crate) async fn rtsp_options(ip: IpAddr, port: u16, timeout: Duration) -> Option<(String, String)> {
    let mut s = connect_or_none(SocketAddr::new(ip, port), timeout).await?;
    s.write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n").await.ok()?;
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, s.read(&mut buf)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    let status = text.lines().next()?.to_string();
    if !status.starts_with("RTSP/1.") {
        return None;
    }
    let server = text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .map(|l| l.split_once(':').unwrap().1.trim().to_string())
        .unwrap_or_default();
    Some((status, server))
}

// ---------- ONVIF ----------

pub struct OnvifProbe;

const ONVIF_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">\
<SOAP-ENV:Body><tds:GetSystemDateAndTime/></SOAP-ENV:Body></SOAP-ENV:Envelope>";

probe_impl!(OnvifProbe, "active:onvif", |ip: IpAddr, hint: &ProbeHint| async move {

        let mut out = Vec::new();
        for port in [80u16, 8080] {
            let body = format!(
                "POST /onvif/device_service HTTP/1.1\r\nHost: {ip}\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                ONVIF_BODY.len(),
                ONVIF_BODY
            );
            let Some((status_code, resp)) =
                http_roundtrip(ip, port, &body, 4096, hint.timeout).await
            else { continue };
            if matches!(status_code, 404 | 502 | 503) {
                continue;
            }
            if !resp.to_ascii_lowercase().contains("onvif") {
                continue;
            }
            let mut e = ev("active:onvif", "onvif_response", ip, 0.9);
            e.port = port as i64;
            let mut rd = BTreeMap::new();
            rd.insert("status_code".into(), status_code.to_string());
            if let Some(server) = header_value(&resp, "server") {
                rd.insert("server".into(), server);
            }
            if resp.to_ascii_lowercase().contains("unauthorized") || status_code == 401 {
                rd.insert("auth_required".into(), "true".into());
            }
            e.raw_data = Some(rd);
            out.push(e);
        }
        out
});

// ---------- /metrics ----------

pub struct MetricsProbe;

probe_impl!(MetricsProbe, "active:http_metrics", |ip: IpAddr, hint: &ProbeHint| async move {

        let mut out = Vec::new();
        for port in [9090u16, 9100] {
            let req = format!("GET /metrics HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n");
            let Some((status_code, resp)) =
                http_roundtrip(ip, port, &req, 4096, hint.timeout).await
            else { continue };
            if status_code != 200 {
                continue;
            }
            let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
            let sample: String = body.chars().take(512).collect();
            if sample.is_empty() {
                continue;
            }
            let mut e = ev("active:http_metrics", "metric", ip, 0.9);
            e.port = port as i64;
            e.raw_data = Some(BTreeMap::from([
                ("content_sample".into(), sample),
                ("url".into(), format!("http://{ip}:{port}/metrics")),
            ]));
            out.push(e);
        }
        out
});

// ---------- shared ----------

async fn connect_or_none(addr: SocketAddr, timeout: Duration) -> Option<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()
}

/// Write a raw request, read up to `max` bytes, return (status_code, raw).
pub(crate) async fn http_roundtrip(
    ip: IpAddr,
    port: u16,
    raw_request: &str,
    max: usize,
    timeout: Duration,
) -> Option<(u16, String)> {
    let mut s = connect_or_none(SocketAddr::new(ip, port), timeout).await?;
    s.write_all(raw_request.as_bytes()).await.ok()?;
    let mut buf = vec![0u8; max];
    let n = tokio::time::timeout(timeout, s.read(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())?;
    Some((status, text))
}

pub(crate) fn header_value(resp: &str, name: &str) -> Option<String> {
    resp.lines()
        .take_while(|l| !l.is_empty())
        .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
        .map(|l| l.split_once(':').unwrap().1.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::oui::Oui;
    use std::sync::Arc;

    fn hint(timeout: Duration) -> ProbeHint {
        ProbeHint {
            community_override: None,
            timeout,
            community: "public".into(),
            port_spec: vec![554, 8554, 80, 8080, 9090, 9100],
            snmp_port: 161,
            mdns_port: 0,
            rdns_servers: vec![],
            oui: Arc::new(Oui::parse("")),
            snmp_v3: None,
        }
    }

    #[tokio::test]
    async fn rtsp_probe_matches_rtsp_status_only() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 128];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision-IPCamera\r\n\r\n").await;
            }
        });
        let (status, server) = rtsp_options("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2))
            .await
            .expect("ephermeral rtsp listener");
        assert!(status.starts_with("RTSP/1.0 200"));
        assert_eq!(server, "Hikvision-IPCamera");
        // non-RTSP status line is rejected by the gate
        let http_like = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hport = http_like.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = http_like.accept().await {
                let mut b = [0u8; 128];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK
Server: x

").await;
            }
        });
        assert!(
            rtsp_options("127.0.0.1".parse().unwrap(), hport, Duration::from_secs(2))
                .await
                .is_none(),
            "HTTP status line must fail the RTSP gate"
        );
    }

    #[tokio::test]
    async fn onvif_probe_emits_with_namespace() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = "<s:Body xmlns:onvif=\"http://www.onvif.org/ver10/soap\"><GetSystemDateAndTimeResponse/></s:Body>";
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()).await;
            }
        });
        // ONVIF probes ports [80, 8080] fixed; bind those is not possible in
        // tests, so exercise http_roundtrip + namespace check directly.
        let (code, resp) = http_roundtrip(
            "127.0.0.1".parse().unwrap(),
            port,
            "POST /onvif/device_service HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            4096,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(code, 200);
        assert!(resp.to_ascii_lowercase().contains("onvif"));
    }

    #[tokio::test]
    async fn metrics_probe_emits_sample() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nnode_exporter 1.6.1\nhttp_requests_total 42\n").await;
            }
        });
        let (code, resp) = http_roundtrip(
            "127.0.0.1".parse().unwrap(),
            port,
            "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            4096,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(code, 200);
        assert!(resp.contains("node_exporter"));
    }
}
