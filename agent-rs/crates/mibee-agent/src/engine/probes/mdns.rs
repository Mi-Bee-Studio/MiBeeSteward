//! mDNS probe: 8 PTR service queries to 224.0.0.251:5353, one socket, 3s
//! window, replies filtered by source IP == target; one evidence per
//! matching packet with hostname/services/txt.* fields (Go
//! probe/udp_discovery.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};
use crate::engine::dns::{build_ptr_query, encode_name, parse_message, Message, RData, RR};

pub struct MdnsProbe;

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

probe_impl!(MdnsProbe, "active:mdns", |ip: IpAddr, hint: &ProbeHint| async move {

        let timeout = MDNS_TIMEOUT.min(hint.timeout * 2); // capped by caller hint semantics
        let IpAddr::V4(_target) = ip else { return Vec::new() };
        let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else { return Vec::new() };
        let mcast: SocketAddr = "224.0.0.251:5353".parse().unwrap();
        for (i, (svc, meta)) in MDNS_SERVICES.iter().enumerate() {
            let qname = if *meta { svc.to_string() } else { format!("{svc}.local") };
            let q = build_ptr_query(&qname, 0x1000 + i as u16, false);
            let _ = sock.send_to(&q, mcast).await;
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
});

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
}
