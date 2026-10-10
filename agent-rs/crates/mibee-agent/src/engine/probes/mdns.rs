//! mDNS probe: 8 PTR service queries to 224.0.0.251:5353, one socket, 3s
//! window, replies filtered by source IP == target; one evidence per
//! matching packet with hostname/services/txt.* fields (Go
//! probe/udp_discovery.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};
use crate::engine::dns::{build_ptr_query, encode_name, parse_message, Message, RData, RR};

/// `unicast` (Go MDNSConfig.UnicastQueries, #20 / #504 parity): additionally
/// send each query straight to the target's 5353 port. Some devices answer
/// unicast mDNS but never answer multicast (responder off or filtered); the
/// reply still arrives at our socket and the source-IP filter keeps
/// cross-talk bounded. One extra packet per query.
#[derive(Default)]
pub struct MdnsProbe {
    pub unicast: bool,
}

const MDNS_SERVICES: [(&str, bool); 8] = [
    ("_services._dns-sd", true), // meta query, no .local suffix conventionally appended
    ("_onvif._tcp", false),
    ("_rtsp._tcp", false),
    ("_http._tcp", false),
    ("_airplay._tcp", false),
    ("_googlecast._tcp", false),
    ("_smb._tcp", false),
    ("_ssh._tcp", false),
];

const MDNS_TIMEOUT: Duration = Duration::from_secs(3);

impl Probe for MdnsProbe {
    fn name(&self) -> &'static str {
        "active:mdns"
    }
    fn probe<'a>(
        &'a self,
        ip: IpAddr,
        hint: &'a ProbeHint,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Evidence>> + Send + 'a>> {
        Box::pin(async move {
            let unicast = self.unicast;
            let timeout = MDNS_TIMEOUT.min(hint.timeout * 2); // capped by caller hint semantics
            let IpAddr::V4(_target) = ip else { return Vec::new() };
            let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else { return Vec::new() };
            let mcast: SocketAddr = "224.0.0.251:5353".parse().unwrap();
            for (i, (svc, meta)) in MDNS_SERVICES.iter().enumerate() {
                let qname = if *meta { svc.to_string() } else { format!("{svc}.local") };
                let q = build_ptr_query(&qname, 0x1000 + i as u16, false);
                let _ = sock.send_to(&q, mcast).await;
                // Unicast fallback (Go #20 parity): also ask the target directly.
                if unicast {
                    let port = if hint.mdns_port != 0 { hint.mdns_port } else { 5353 };
                    let _ = sock.send_to(&q, SocketAddr::new(ip, port)).await;
                }
            }
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        let mut buf = [0u8; 9000];
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
                continue; // only the target's own announcements count
            }
            if let Ok(msg) = parse_message(&buf[..n]) {
                if let Some(e) = message_to_evidence(ip, &msg) {
                    out.push(e);
                }
            }
        }
            out
        })
    }
}

/// Fold one mDNS response into evidence: instance names as hostname, PTR
/// targets as services, TXT keys as txt.<key>.
pub fn message_to_evidence(ip: IpAddr, msg: &Message) -> Option<Evidence> {
    let mut rd: BTreeMap<String, String> = BTreeMap::new();
    let mut hostname: Option<String> = None;
    let mut services: Vec<String> = Vec::new();
    let all: Vec<&RR> = msg.answers.iter().chain(msg.additional.iter()).collect();
    for rr in &all {
        match &rr.rdata {
            RData::Ptr(target) => {
                // The service TYPE is the RR name ("_smb._tcp.local"); the
                // rdata target names the instance ("<inst>._smb._tcp.local").
                let svc = rr.name.trim_end_matches(".local");
                if svc.starts_with('_') {
                    services.push(svc.to_string());
                } else {
                    services.push(target.trim_end_matches(".local").to_string());
                }
                if hostname.is_none() {
                    if let Some(instance) = target.split('.').next() {
                        if !instance.starts_with('_') && instance.len() > 1 {
                            hostname = Some(instance.to_string());
                        }
                    }
                }
            }
            RData::Txt(strs) => {
                for s in strs {
                    if let Some((k, v)) = s.split_once('=') {
                        if !v.is_empty() && v.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                            rd.insert(format!("txt.{k}"), v.to_string());
                        }
                    }
                }
            }
            RData::Srv { target, .. } => {
                if hostname.is_none() {
                    if let Some(instance) = target.trim_end_matches(".local").split('.').next() {
                        if !instance.starts_with('_') && instance.len() > 1 {
                            hostname = Some(instance.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if hostname.is_some() {
        rd.insert("hostname".into(), hostname.unwrap_or_default());
    }
    if !services.is_empty() {
        rd.insert("services".into(), services.join(","));
    }
    if rd.is_empty() {
        return None;
    }
    let mut e = ev("active:mdns", "mdns", ip, 0.85);
    e.port = 5353;
    e.protocol = "udp".into();
    e.raw_data = Some(rd);
    Some(e)
}

#[allow(dead_code)]
pub(crate) fn _encode_helper(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    encode_name(name, &mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(name: &str, rdata: RData) -> RR {
        RR { name: name.into(), rtype: match rdata {
            RData::Ptr(_) => 12,
            RData::Txt(_) => 16,
            RData::Srv { .. } => 33,
            RData::A(_) => 1,
            RData::Other(t) => t,
        }, rdata }
    }

    #[test]
    fn folds_ptr_txt_and_srv() {
        let mut msg = Message::default();
        msg.answers.push(rr("_smb._tcp.local", RData::Ptr("NAS-BOX._smb._tcp.local".into())));
        msg.additional.push(rr("NAS-BOX._smb._tcp.local", RData::Txt(vec![
            "model=DS920+".into(),
            "vendor=Synology".into(),
        ])));
        msg.additional.push(rr("_ssh._tcp.local", RData::Srv {
            prio: 0,
            weight: 0,
            port: 22,
            target: "nas-box.local".into(),
        }));
        let e = message_to_evidence("192.0.2.9".parse().unwrap(), &msg).unwrap();
        let rd = e.raw_data.unwrap();
        assert_eq!(rd["hostname"], "NAS-BOX");
        assert_eq!(rd["services"], "_smb._tcp");
        assert_eq!(rd["txt.model"], "DS920+");
        assert_eq!(rd["txt.vendor"], "Synology");
    }

    #[test]
    fn empty_message_no_evidence() {
        assert!(message_to_evidence("192.0.2.9".parse().unwrap(), &Message::default()).is_none());
    }

    /// Go parity (#504): with unicast_queries on, the probe also asks the
    /// target's 5353 directly — a device that never answers multicast but does
    /// answer unicast still produces evidence. A responder bound to
    /// 127.0.0.1:5353 stands in for the target; the probe's source-IP filter
    /// accepts it.
    #[tokio::test]
    async fn unicast_query_reaches_unicast_only_responder() {
        use crate::engine::dns::encode_name;

        // Minimal mDNS response on the wire: header (QR+AA, 1 answer) +
        // PTR _smb._tcp.local -> NAS-BOX._smb._tcp.local.
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x00, 0x00, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
        encode_name("_smb._tcp.local", &mut resp);
        resp.extend_from_slice(&12u16.to_be_bytes()); // PTR
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&120u32.to_be_bytes()); // TTL
        let mut rdata = Vec::new();
        encode_name("NAS-BOX._smb._tcp.local", &mut rdata);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind responder");
        let mdns_port = listener.local_addr().unwrap().port();
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, from) = listener.recv_from(&mut buf).await.expect("recv query");
            listener.send_to(&resp, from).await.expect("send reply");
        });

        let hint = ProbeHint {
            community_override: None,
            timeout: Duration::from_millis(700),
            community: "public".into(),
            port_spec: vec![],
            snmp_port: 161,
            mdns_port,
            rdns_servers: vec![],
            oui: std::sync::Arc::new(crate::engine::oui::Oui::parse("")),
            snmp_v3: None,
        };
        let probe = MdnsProbe { unicast: true };
        let out = probe.probe("127.0.0.1".parse().unwrap(), &hint).await;
        responder.await.unwrap();
        assert!(!out.is_empty(), "{out:?}");
        let e = &out[0];
        assert_eq!(e.kind, "mdns");
        assert_eq!(e.raw_data.as_ref().unwrap()["hostname"], "NAS-BOX");
    }
}
