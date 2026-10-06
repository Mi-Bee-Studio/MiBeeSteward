//! SSDP probe: 2x M-SEARCH (ST: ssdp:all, MX: 2) to 239.255.255.250:1900,
//! 3s window, source-IP filtered, needs >=2 of server/location/st/usn
//! (Go probe/udp_discovery.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

pub struct SsdpProbe;

const SSDP_TIMEOUT: Duration = Duration::from_secs(3);

probe_impl!(SsdpProbe, "active:ssdp", |ip: IpAddr, hint: &ProbeHint| async move {

        let _ = hint;
        let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else { return Vec::new() };
        let addr: SocketAddr = "239.255.255.250:1900".parse().unwrap();
        let search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
        let _ = sock.send_to(search.as_bytes(), addr).await;
        let _ = sock.send_to(search.as_bytes(), addr).await;
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + SSDP_TIMEOUT;
        let mut buf = [0u8; 4096];
        loop {
            let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remain.is_zero() {
                break;
            }
            let Ok(Ok((n, from))) = tokio::time::timeout(remain, sock.recv_from(&mut buf)).await
            else {
                break;
            };
            if from.ip() != ip {
                continue;
            }
            if let Some(e) = parse_ssdp_response(ip, &String::from_utf8_lossy(&buf[..n])) {
                out.push(e);
            }
        }
        out
});

pub fn parse_ssdp_response(ip: IpAddr, text: &str) -> Option<Evidence> {
    let mut server = String::new();
    let mut location = String::new();
    let mut st = String::new();
    let mut usn = String::new();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "server" => server = v.to_string(),
            "location" => location = v.to_string(),
            "st" => st = v.to_string(),
            "usn" => usn = v.to_string(),
            _ => {}
        }
    }
    let mut rd = BTreeMap::new();
    if !server.is_empty() {
        rd.insert("server".into(), server);
    }
    if !location.is_empty() {
        rd.insert("location".into(), location);
    }
    if !st.is_empty() {
        rd.insert("st".into(), st);
    }
    if !usn.is_empty() {
        rd.insert("usn".into(), usn);
    }
    if rd.len() < 2 {
        return None; // needs >=2 fields
    }
    let mut e = ev("active:ssdp", "ssdp", ip, 0.8);
    e.port = 1900;
    e.raw_data = Some(rd);
    e.observed_at = crate::wire::now_rfc3339();
    Some(e)
}

#[allow(dead_code)]
fn unused(_t: SystemTime) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_response_and_requires_two_fields() {
        let resp = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: lunzn,fastrhino-r68s UPnP/1.1 MiniUPnPd/2.2.1\r\nLOCATION: http://192.0.2.1:5000/rootDesc.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n";
        let e = parse_ssdp_response("192.0.2.1".parse().unwrap(), resp).unwrap();
        let rd = e.raw_data.unwrap();
        assert_eq!(rd["server"], "lunzn,fastrhino-r68s UPnP/1.1 MiniUPnPd/2.2.1");
        assert_eq!(rd["location"], "http://192.0.2.1:5000/rootDesc.xml");
        // only one field present -> dropped
        assert!(parse_ssdp_response("192.0.2.1".parse().unwrap(), "HTTP/1.1 200 OK\r\nST: x\r\n\r\n").is_none());
    }
}
