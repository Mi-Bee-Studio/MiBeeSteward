//! WS-Discovery probe (#507): 2x Probe SOAP to 239.255.255.250:3702, 2s
//! window, source-IP filtered, ProbeMatches parsed for ONVIF identity
//! (types/scopes/xaddrs/address; onvif:// scope URIs unpacked + percent
//! decoded). Go probe/wsdiscovery.go parity.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{probe_impl, Evidence, Probe, ProbeHint};

pub struct WsDiscoveryProbe;

const WSD_TIMEOUT: Duration = Duration::from_secs(2);

const WSD_PROBE_MESSAGE: &str = concat!(
    r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" "#,
    r#"xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">"#,
    "<s:Header>",
    r#"<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>"#,
    "<a:MessageID>urn:uuid:mibee-steward-probe</a:MessageID>",
    r#"<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>"#,
    "</s:Header>",
    r#"<s:Body><Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/></s:Body>"#,
    "</s:Envelope>"
);

probe_impl!(
    WsDiscoveryProbe,
    "active:wsdiscovery",
    |ip: IpAddr, hint: &ProbeHint| async move {
        let _ = hint;
        let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            return Vec::new();
        };
        let addr: SocketAddr = "239.255.255.250:3702".parse().unwrap();
        let _ = sock.send_to(WSD_PROBE_MESSAGE.as_bytes(), addr).await;
        let _ = sock.send_to(WSD_PROBE_MESSAGE.as_bytes(), addr).await;
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + WSD_TIMEOUT;
        let mut buf = [0u8; 8192];
        loop {
            let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remain.is_zero() {
                break;
            }
            let Ok(Ok((n, from))) = tokio::time::timeout(remain, sock.recv_from(&mut buf)).await
            else {
                break;
            };
            // Strict source filter (#507 acceptance): a multicast Probe is
            // answered by EVERY WS-D device on the segment; only the
            // target's own ProbeMatch becomes its evidence.
            if from.ip() != ip {
                continue;
            }
            if let Some(e) = parse_wsdiscovery_match(ip, &String::from_utf8_lossy(&buf[..n])) {
                out.push(e);
            }
        }
        out
    }
);

/// Parse one ProbeMatches datagram into evidence. Field extraction is
/// tag-text based (no XML dep in this crate): the SOAP bodies seen in the
/// wild are machine-generated and regular; anything without a ProbeMatch
/// element yields None (Hello/Bye/garbage ignored).
pub fn parse_wsdiscovery_match(ip: IpAddr, text: &str) -> Option<Evidence> {
    if !text.contains("ProbeMatch") {
        return None;
    }
    let types = tag_text(text, "Types");
    let xaddrs = tag_text(text, "XAddrs");
    let address = tag_text(text, "Address");
    let scopes = attr_value(text, "Scopes", "value");
    if types.is_none() && xaddrs.is_none() && scopes.is_none() && address.is_none() {
        return None;
    }
    let mut raw = BTreeMap::new();
    if let Some(v) = &types {
        raw.insert("types".to_string(), v.clone());
    }
    if let Some(v) = &xaddrs {
        raw.insert("xaddrs".to_string(), v.clone());
    }
    if let Some(v) = &address {
        raw.insert("address".to_string(), v.clone());
    }
    if let Some(v) = &scopes {
        raw.insert("scopes".to_string(), v.clone());
        // Unpack onvif://www.onvif.org/<key>/<value> URIs, percent-decoded.
        for (k, val) in onvif_scopes(v) {
            raw.entry(k).or_insert(val);
        }
    }
    raw.insert("service_hint".to_string(), "onvif".to_string());
    Some(Evidence {
        source: "active:wsdiscovery".into(),
        kind: "wsdiscovery".into(),
        ip: ip.to_string(),
        port: 3702,
        protocol: "udp".into(),
        confidence: 0.85,
        raw_data: Some(raw),
        observed_at: crate::wire::now_rfc3339(),
        ..Default::default()
    })
}

/// Extract the inner text of the FIRST `<...:Tag>text</...:Tag>` occurrence,
/// namespace-prefix agnostic.
fn tag_text(text: &str, tag: &str) -> Option<String> {
    let start = text.find(&format!(":{tag}>"))? + tag.len() + 2;
    let rest = &text[start..];
    let end = rest.find("</")?;
    let v = rest[..end].trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// Extract `attr="value"` from the first `<...Tag attr="value"` occurrence.
fn attr_value(text: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_at = text
        .find(&format!("<{}:", tag))
        .or_else(|| text.find(&format!(":{tag} ")))?;
    let window = &text[tag_at..];
    let needle = format!("{attr}=\"");
    let vstart = window.find(&needle)? + needle.len();
    let rest = &window[vstart..];
    let vend = rest.find('"')?;
    let v = &rest[..vend];
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// onvif://www.onvif.org/<key>/<percent-escaped value> unpacking; the first
/// occurrence of a key wins (same policy as the Go parser).
pub fn onvif_scopes(scopes: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for tok in scopes.split_whitespace() {
        let tok = tok.trim_matches('"');
        let Some(rest) = tok.strip_prefix("onvif://www.onvif.org/") else {
            continue;
        };
        let Some((key, value)) = rest.split_once('/') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if !out.iter().any(|(k, _)| k == key) {
            out.push((key.to_string(), unescape_scope(value)));
        }
    }
    out
}

/// %XX decoding for scope values (names carry %20 spaces etc.).
fn unescape_scope(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <d:ProbeMatch>
        <a:EndpointReference><a:Address>urn:uuid:1e2d3c4b-5a69-7788-99aa-bbccddeeff00</a:Address></a:EndpointReference>
        <d:Types>tds:NetworkVideoTransmitter</d:Types>
        <d:Scopes value="onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/IPC-122"/>
        <d:XAddrs>http://192.0.2.42:8080/onvif/device_service</d:XAddrs>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>"#;

    #[test]
    fn parses_probe_matches() {
        let ip: IpAddr = "192.0.2.42".parse().unwrap();
        let e = parse_wsdiscovery_match(ip, SAMPLE).expect("parses");
        assert_eq!(e.kind, "wsdiscovery");
        assert_eq!(e.source, "active:wsdiscovery");
        assert_eq!(e.port, 3702);
        let raw = e.raw_data.unwrap();
        assert_eq!(raw["types"], "tds:NetworkVideoTransmitter");
        assert_eq!(raw["xaddrs"], "http://192.0.2.42:8080/onvif/device_service");
        assert_eq!(
            raw["address"],
            "urn:uuid:1e2d3c4b-5a69-7788-99aa-bbccddeeff00"
        );
        assert_eq!(raw["name"], "Front Door"); // %20 decoded
        assert_eq!(raw["hardware"], "IPC-122");
        assert_eq!(raw["service_hint"], "onvif");
    }

    #[test]
    fn ignores_hello_and_garbage() {
        let ip: IpAddr = "192.0.2.42".parse().unwrap();
        let hello = "<s:Body><d:Hello xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><d:Types>x</d:Types></d:Hello></s:Body>";
        assert!(parse_wsdiscovery_match(ip, hello).is_none());
        assert!(parse_wsdiscovery_match(ip, "not xml").is_none());
        assert!(parse_wsdiscovery_match(ip, "").is_none());
    }

    #[test]
    fn scope_unpack_first_wins_and_decodes() {
        let got = onvif_scopes("\"onvif://www.onvif.org/name/Cam%2B1\" \"onvif://www.onvif.org/name/Second\" http://x/y");
        assert_eq!(got, vec![("name".to_string(), "Cam+1".to_string())]);
        assert!(onvif_scopes("http://only/foreign").is_empty());
    }
}
