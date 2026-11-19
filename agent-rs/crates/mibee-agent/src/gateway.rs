//! Gateway profile probe (#752 UPnP IGD, #753 NAT mapping behavior) — the
//! "can do what" half of the router asset, against PUBLIC STUN servers only
//! (the center ships the list; the product carries no self-hosted STUN).
//!
//! Pure helpers are TDD'd without sockets: SSDP response parsing, device
//! description / SOAP response extraction, STUN codec (the Rust twin of the
//! center's RFC 5389 client), and the mapping-behavior classifier. The live
//! runner glues them together and is best-effort by contract: a failed
//! section reports its default, never wedges the command loop.

use std::collections::BTreeMap;
use std::time::Duration;

/// One gateway-profile round's outcome, the complete_command payload of the
/// `gateway_probe` command (#753). Every field is optional evidence: a dead
/// section stays at its default rather than inventing a value.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GatewayReport {
    /// RFC3339 UTC, probe clock.
    #[serde(default)]
    pub checked_at: String,
    // UPnP IGD (#752)
    #[serde(default)]
    pub upnp_available: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub upnp_server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wan_ip: String,
    #[serde(default)]
    pub port_mapping_ok: bool,
    // NAT mapping behavior (#753)
    /// eim (endpoint-independent = cone) | edm (endpoint-dependent =
    /// symmetric) | unknown (fewer than two responsive servers).
    #[serde(default)]
    pub nat_mapping: String,
    /// Public mapping the probe saw (extra evidence for the WAN row).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_ip: String,
    /// How many STUN servers answered.
    #[serde(default)]
    pub stun_servers_seen: i64,
    #[serde(default)]
    pub hole_punch_viable: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// Build the SSDP M-SEARCH datagram for IGD devices (#752). Several ST
/// values — devices answer inconsistently; one datagram per target.
pub(crate) fn build_ssdp_search(st: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n"
    )
}

/// Extract the Location header from an SSDP M-SEARCH response
/// (case-insensitive; SSDP devices vary).
pub(crate) fn parse_ssdp_location(response: &str) -> Option<String> {
    for line in response.lines() {
        let (name, value) = match line.split_once(':') {
            Some((n, v)) => (n.trim().to_ascii_uppercase(), v.trim()),
            None => continue,
        };
        if name == "LOCATION" && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// Build the WANIPConnection GetExternalIPAddress SOAP request.
pub(crate) fn build_wan_ip_soap(control_url: &str, service_type: &str) -> String {
    format!(
        "POST {control_url} HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCONTENT-LENGTH: 278\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nSOAPACTION: \"{service_type}#GetExternalIPAddress\"\r\n\r\n\
<?xml version=\"1.0\"?>\r\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:GetExternalIPAddress xmlns:m=\"{service_type}\"/></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

/// Extract NewExternalIPAddress from a SOAP response body.
pub(crate) fn parse_soap_wan_ip(body: &str) -> Option<String> {
    const OPEN: &str = "<NewExternalIPAddress>";
    const CLOSE: &str = "</NewExternalIPAddress>";
    let start = body.find(OPEN)? + OPEN.len();
    let end = body[start..].find(CLOSE)? + start;
    let ip = body[start..end].trim();
    if ip.is_empty() {
        return None;
    }
    Some(ip.to_string())
}

/// The AddPortMapping SOAP request (the mapping IS the capability test:
/// success proves the gateway accepts inbound pinholes).
pub(crate) fn build_add_port_mapping_soap(
    control_url: &str,
    service_type: &str,
    external_port: u16,
    internal_port: u16,
    description: &str,
) -> String {
    let lease = 600; // short-lived; the probe mapping is not for production use
    let body = format!(
        "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><m:AddPortMapping xmlns:m=\"{service_type}\"><NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>{internal_port}</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{description}</NewPortMappingDescription><NewLeaseDuration>{lease}</NewLeaseDuration></m:AddPortMapping></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    );
    format!(
        "POST {control_url} HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCONTENT-LENGTH: {}\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nSOAPACTION: \"{}#AddPortMapping\"\r\n\r\n{}",
        body.len(),
        service_type,
        body
    )
}

/// Detect SOAP fault in a response body (the capability test's failure arm).
pub(crate) fn is_soap_fault(body: &str) -> bool {
    body.contains("<SOAP-ENV:Fault>") || body.contains("<s:Fault>") || body.contains(":Fault>")
}

// --- STUN codec (Rust twin of the center's RFC 5389 client) ---

pub(crate) const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// Build a 20-byte Binding Request with a caller-supplied transaction ID
/// (the runner generates randomness; the pure function stays deterministic).
pub(crate) fn build_binding_request(txid: [u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01;
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(&txid);
    req
}

/// Decode a Binding Response: mapped (ip, port) or an error string.
pub(crate) fn parse_binding_response(pkt: &[u8], txid: &[u8; 12]) -> Result<(std::net::IpAddr, u16), String> {
    if pkt.len() < 20 {
        return Err("short".into());
    }
    if pkt[0] != 0x01 || pkt[1] != 0x01 {
        return Err(format!("type {:02x}{:02x}", pkt[0], pkt[1]));
    }
    if pkt[4..8] != STUN_MAGIC_COOKIE.to_be_bytes() {
        return Err("cookie".into());
    }
    if pkt[8..20] != txid[..] {
        return Err("txid".into());
    }
    let mut length = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if 20 + length > pkt.len() {
        length = pkt.len() - 20;
    }
    let mut off = 20usize;
    while off + 4 <= 20 + length {
        let attr = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let alen = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) as usize;
        let body = off + 4;
        if body + alen > pkt.len() {
            return Err("attr overruns".into());
        }
        match attr {
            0x0020 | 0x0001 if alen >= 8 => {
                let xor = attr == 0x0020;
                if pkt[body + 1] != 0x01 {
                    off = body + alen + ((4 - alen % 4) % 4);
                    continue;
                }
                let port = u16::from_be_bytes([pkt[body + 2], pkt[body + 3]]);
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&pkt[body + 4..body + 8]);
                if xor {
                    let c = STUN_MAGIC_COOKIE.to_be_bytes();
                    for i in 0..4 {
                        octets[i] ^= c[i];
                    }
                }
                let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                ));
                let port = if xor { port ^ (STUN_MAGIC_COOKIE >> 16) as u16 } else { port };
                return Ok((ip, port));
            }
            _ => {}
        }
        off = body + alen + ((4 - alen % 4) % 4);
    }
    Err("no mapped address".into())
}

/// NAT mapping-behavior classification (#753): the mapped (ip, port) tuples
/// one shared socket observed from >=2 DISTINCT servers. All tuples identical
/// = endpoint-independent mapping (cone); any difference = endpoint-dependent
/// (symmetric). Fewer than two samples = unknown (never guess).
pub(crate) fn classify_nat(samples: &[(std::net::IpAddr, u16)]) -> &'static str {
    if samples.len() < 2 {
        return "unknown";
    }
    let first = &samples[0];
    if samples.iter().all(|s| s == first) {
        "eim"
    } else {
        "edm"
    }
}

/// Sort/de-dup helper for test readability: unique mapped IPs in order.
pub(crate) fn unique_ips(samples: &[(std::net::IpAddr, u16)]) -> Vec<std::net::IpAddr> {
    let mut seen: Vec<std::net::IpAddr> = Vec::new();
    for (ip, _) in samples {
        if !seen.contains(ip) {
            seen.push(*ip);
        }
    }
    seen
}

/// Live probe round: UPnP IGD discovery + WAN IP + port mapping capability,
/// then the NAT mapping classification across the center-shipped server
/// list. Linux + non-Linux both run (UDP SSDP/STUN need no privileges);
/// every failure lands in `note` and the field stays default.
pub async fn run_gateway_probe(servers: &[String], timeout: Duration) -> GatewayReport {
    let mut report = GatewayReport {
        checked_at: crate::wire::now_rfc3339(),
        nat_mapping: "unknown".into(),
        ..Default::default()
    };
    let mut notes: Vec<String> = Vec::new();

    // --- UPnP IGD (#752) ---
    match upnp_probe(timeout).await {
        Ok((server, wan, mapping_ok)) => {
            report.upnp_available = true;
            report.upnp_server = server;
            if let Some(ip) = wan {
                report.wan_ip = ip;
            }
            report.port_mapping_ok = mapping_ok;
        }
        Err(e) => notes.push(format!("upnp: {e}")),
    }

    // --- NAT mapping behavior (#753) ---
    let mut samples: Vec<(std::net::IpAddr, u16)> = Vec::new();
    for srv in servers.iter().take(8) {
        match stun_query(srv, timeout).await {
            Ok(tuple) => samples.push(tuple),
            Err(e) => notes.push(format!("stun {srv}: {e}")),
        }
    }
    report.stun_servers_seen = samples.len() as i64;
    report.nat_mapping = classify_nat(&samples).to_string();
    if let Some((ip, _)) = samples.first() {
        report.public_ip = ip.to_string();
    }
    report.hole_punch_viable = report.nat_mapping == "eim" && report.upnp_available;
    report.note = notes.join("; ");
    report
}

/// SSDP M-SEARCH -> LOCATION -> device description (control URL) ->
/// GetExternalIPAddress + AddPortMapping. Bounded: one SSDP round (2s
/// budget), one description fetch, one SOAP query, one mapping attempt.
async fn upnp_probe(
    timeout: Duration,
) -> Result<(String, Option<String>, bool), String> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let mut location = None;
    for st in ["upnp:rootdevice", "InternetGatewayDevice"] {
        let search = build_ssdp_search(st);
        if sock.send_to(search.as_bytes(), "239.255.255.250:1900").await.is_err() {
            continue;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2).min(timeout * 2);
        let mut buf = [0u8; 2048];
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let Some(loc) = parse_ssdp_location(&String::from_utf8_lossy(&buf[..n])) {
                        location = Some(loc);
                        break;
                    }
                }
                _ => break,
            }
        }
        if location.is_some() {
            break;
        }
    }
    let Some(location) = location else {
        return Err("no ssdp response".into());
    };

    // The location URL's authority pins the gateway's control plane.
    let (host, control_path) = split_url(&location);
    let desc = http_get(&host, &control_path, timeout).await?;
    let (service_type, control_url) = extract_igd_service(&desc);

    // GetExternalIPAddress.
    let soap = build_wan_ip_soap(&control_url, &service_type);
    let resp = http_post_raw(&host, &control_url, &soap, timeout).await?;
    let wan = parse_soap_wan_ip(&resp);

    // AddPortMapping: success = inbound pinhole capability.
    let map_soap = build_add_port_mapping_soap(&control_url, &service_type, 40001, 40001, "mibee-steward-probe");
    let map_resp = http_post_raw(&host, &control_url, &map_soap, timeout).await?;
    let mapping_ok = !is_soap_fault(&map_resp);

    Ok((location, wan, mapping_ok))
}

/// "http://host:port/path" -> ("host:port", "/path").
pub(crate) fn split_url(url: &str) -> (String, String) {
    let rest = url.split("://").nth(1).unwrap_or(url);
    match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".into()),
    }
}

/// Walk the device-description XML for the WANIPConnection control URL
/// (serviceType + controlURL pairs; first WANIPConnection or WANPPP wins).
pub(crate) fn extract_igd_service(desc: &str) -> (String, String) {
    let mut service_type = String::new();
    let mut control = String::new();
    for svc_type in ["WANIPConnection", "WANPPPConnection"] {
        let tag = svc_type.to_string();
        if let Some(idx) = desc.find(&tag) {
            // Search forward for the closest controlURL after the serviceType
            // mention (the XML may interleave service blocks).
            let tail = &desc[idx..];
            if let Some(cs) = tail.find("<controlURL>") {
                let cs = cs + "<controlURL>".len();
                if let Some(ce) = tail[cs..].find("</controlURL>") {
                    control = tail[cs..cs + ce].trim().to_string();
                    service_type = find_service_type(tail, &tag);
                    if !service_type.is_empty() && !control.is_empty() {
                        return (service_type, control);
                    }
                }
            }
            service_type = find_service_type(tail, &tag);
        }
    }
    if service_type.is_empty() {
        service_type = "urn:schemas-upnp-org:service:WANIPConnection:1".into();
    }
    (service_type, control)
}

/// Pull the full urn:...service:{name}:N serviceType string near a block.
fn find_service_type(tail: &str, name: &str) -> String {
    const OPEN: &str = "<serviceType>";
    let mut search_from = 0;
    while let Some(rel) = tail[search_from..].find(OPEN) {
        let s = search_from + rel + OPEN.len();
        if let Some(e) = tail[s..].find("</serviceType>") {
            let v = tail[s..s + e].trim();
            if v.contains(name) {
                return v.to_string();
            }
            search_from = s + e;
        } else {
            break;
        }
    }
    format!("urn:schemas-upnp-org:service:{name}:1")
}

/// Minimal blocking-free HTTP/1.1 GET over raw TCP (no TLS: IGD control is
/// plain HTTP on the LAN; anything else would not be an IGD anyway).
async fn http_get(host: &str, path: &str, timeout: Duration) -> Result<String, String> {
    let req = format!("GET {path} HTTP/1.1\r\nHOST: {host}\r\nCONNECTION: close\r\n\r\n");
    raw_http(host, &req, timeout).await
}

async fn http_post_raw(host: &str, path: &str, req: &str, timeout: Duration) -> Result<String, String> {
    let _ = path;
    raw_http(host, req, timeout).await
}

async fn raw_http(host: &str, req: &str, timeout: Duration) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(host))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::with_capacity(4096);
    tokio::time::timeout(timeout, stream.read_to_end(&mut buf))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    let raw = String::from_utf8_lossy(&buf);
    // Split headers/body: the SOAP payload starts after the blank line.
    match raw.find("\r\n\r\n") {
        Some(i) => Ok(raw[i + 4..].to_string()),
        None => Ok(raw.to_string()),
    }
}

/// One STUN Binding Request to `server` ("host:port", 3478 implied) from a
/// fresh socket — the NAT classifier's per-server sample.
async fn stun_query(server: &str, timeout: Duration) -> Result<(std::net::IpAddr, u16), String> {
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:3478")
    };
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let mut txid = [0u8; 12];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut txid))
        .is_err()
    {
        // Deterministic fallback is fine for a measurement id.
        let now = crate::wire::now_rfc3339();
        for (i, b) in now.bytes().take(12).enumerate() {
            txid[i] = b;
        }
    }
    let req = build_binding_request(txid);
    sock.send_to(&req, &addr).await.map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("recv: {e}"))?;
    parse_binding_response(&buf[..n], &txid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_search_shape() {
        let s = build_ssdp_search("upnp:rootdevice");
        assert!(s.starts_with("M-SEARCH * HTTP/1.1"));
        assert!(s.contains("ST: upnp:rootdevice"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn ssdp_location_extraction() {
        let resp = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nlocation: http://192.0.2.1:5000/rootDesc.xml\r\nSERVER: Linux/1.0 UPnP/1.0\r\n\r\n";
        assert_eq!(
            parse_ssdp_location(resp),
            Some("http://192.0.2.1:5000/rootDesc.xml".to_string())
        );
        assert_eq!(parse_ssdp_location("HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn soap_wan_ip_extraction() {
        let body = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope><SOAP-ENV:Body><m:GetExternalIPAddressResponse xmlns:m=\"urn:x\"><NewExternalIPAddress>203.0.113.4</NewExternalIPAddress></m:GetExternalIPAddressResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>";
        assert_eq!(parse_soap_wan_ip(body), Some("203.0.113.4".to_string()));
        assert_eq!(parse_soap_wan_ip("<Fault></Fault>"), None);
        assert_eq!(parse_soap_wan_ip("<NewExternalIPAddress></NewExternalIPAddress>"), None);
    }

    #[test]
    fn soap_fault_detection() {
        assert!(is_soap_fault("<SOAP-ENV:Body><SOAP-ENV:Fault><faultstring>OnlyOnePortMapping</faultstring>"));
        assert!(is_soap_fault("<s:Fault>"));
        assert!(!is_soap_fault("<NewExternalIPAddress>1.2.3.4</NewExternalIPAddress>"));
    }

    #[test]
    fn igd_service_extraction() {
        let desc = "<?xml?><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL></service></serviceList></device>";
        let (st, ctrl) = extract_igd_service(desc);
        assert_eq!(st, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(ctrl, "/ctl/IPConn");
    }

    #[test]
    fn igd_service_falls_back_to_defaults() {
        let (st, ctrl) = extract_igd_service("<device><serviceList></serviceList></device>");
        assert!(st.contains("WANIPConnection"), "{st}");
        assert_eq!(ctrl, "");
    }

    #[test]
    fn url_split() {
        assert_eq!(split_url("http://192.0.2.1:5000/rootDesc.xml"), ("192.0.2.1:5000".to_string(), "/rootDesc.xml".to_string()));
        assert_eq!(split_url("192.0.2.1:5000"), ("192.0.2.1:5000".to_string(), "/".to_string()));
    }

    #[test]
    fn binding_request_shape() {
        let txid = [7u8; 12];
        let req = build_binding_request(txid);
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        assert_eq!(&req[4..8], &STUN_MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&req[8..20], &txid[..]);
    }

    /// Craft a response the same way the center's Go test fake does, then
    /// decode: the Rust twin must agree.
    #[test]
    fn binding_response_xor_roundtrip() {
        let txid = [0x5Au8; 12];
        let ip = std::net::Ipv4Addr::new(198, 51, 100, 7);
        let port = 51234u16;
        let mut pkt = vec![0u8; 20 + 12];
        pkt[0] = 0x01;
        pkt[1] = 0x01;
        pkt[2..4].copy_from_slice(&12u16.to_be_bytes());
        pkt[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        pkt[8..20].copy_from_slice(&txid);
        pkt[20..22].copy_from_slice(&0x0020u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&8u16.to_be_bytes());
        pkt[24] = 0;
        pkt[25] = 0x01;
        pkt[26..28].copy_from_slice(&(port ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let c = STUN_MAGIC_COOKIE.to_be_bytes();
        for i in 0..4 {
            pkt[28 + i] = ip.octets()[i] ^ c[i];
        }
        let (got_ip, got_port) = parse_binding_response(&pkt, &txid).expect("decode");
        assert_eq!(got_ip, std::net::IpAddr::V4(ip));
        assert_eq!(got_port, port);
    }

    #[test]
    fn nat_classifier() {
        let a: std::net::IpAddr = "203.0.113.1".parse().unwrap();
        let b: std::net::IpAddr = "203.0.113.2".parse().unwrap();
        assert_eq!(classify_nat(&[]), "unknown");
        assert_eq!(classify_nat(&[(a, 5000)]), "unknown");
        assert_eq!(classify_nat(&[(a, 5000), (a, 5000), (a, 5000)]), "eim");
        assert_eq!(classify_nat(&[(a, 5000), (a, 5001)]), "edm", "same ip, different port = edm");
        assert_eq!(classify_nat(&[(a, 5000), (b, 5001)]), "edm");
    }

    #[test]
    fn unique_ips_dedup() {
        let a: std::net::IpAddr = "203.0.113.1".parse().unwrap();
        let b: std::net::IpAddr = "203.0.113.2".parse().unwrap();
        assert_eq!(unique_ips(&[(a, 1), (a, 1), (b, 2)]), vec![a, b]);
    }

    /// The full report serializer stays snake_case for the center's JSON.
    #[test]
    fn gateway_report_wire_shape() {
        let r = GatewayReport {
            checked_at: "2026-11-18T12:00:00Z".into(),
            upnp_available: true,
            wan_ip: "203.0.113.9".into(),
            nat_mapping: "eim".into(),
            stun_servers_seen: 5,
            ..Default::default()
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["upnp_available"], true);
        assert_eq!(v["wan_ip"], "203.0.113.9");
        assert_eq!(v["nat_mapping"], "eim");
        assert_eq!(v["stun_servers_seen"], 5);
        assert!(v.get("upnp_server").is_none(), "empty skips");
        let back: GatewayReport = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
    }
}
