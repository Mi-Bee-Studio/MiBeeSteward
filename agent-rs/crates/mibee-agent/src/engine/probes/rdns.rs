//! rDNS probe: PTR lookup over UDP 53 against the configured servers (or
//! the first nameserver in /etc/resolv.conf), trailing dot stripped,
//! confidence 0.8 (Go probe/rdns.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};
use crate::engine::dns::{build_ptr_query, parse_message, RData};

pub struct RdnsProbe;

probe_impl!(RdnsProbe, "active:rdns", |ip: IpAddr, hint: &ProbeHint| async move {

        let servers = if !hint.rdns_servers.is_empty() {
            hint.rdns_servers.clone()
        } else {
            system_nameservers().await
        };
        for server in servers {
            if let Some(name) = ptr_lookup(ip, &server, hint.timeout).await {
                let mut e = ev("active:rdns", "hostname", ip, 0.8);
                e.raw_data = Some(BTreeMap::from([("hostname".into(), name)]));
                return vec![e];
            }
        }
        Vec::new()
});

/// First-success PTR resolution; empty result on NXDOMAIN-ish answers.
pub async fn ptr_lookup(ip: IpAddr, server: &str, timeout: Duration) -> Option<String> {
    let qname = reverse_ptr_name(ip);
    let id = (std::process::id() as u16).wrapping_mul(31);
    let q = build_ptr_query(&qname, id, true);
    let Ok(addr) = server.parse::<SocketAddr>() else { return None };
    let sock = tokio::net::UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .await
        .ok()?;
    sock.connect(addr).await.ok()?;
    sock.send(&q).await.ok()?;
    let mut buf = vec![0u8; 1500];
    let Ok(Ok(n)) = tokio::time::timeout(timeout, sock.recv(&mut buf)).await else { return None };
    let msg = parse_message(&buf[..n]).ok()?;
    for rr in msg.answers.iter().chain(msg.additional.iter()) {
        if let RData::Ptr(name) = &rr.rdata {
            if !name.is_empty() {
                return Some(name.trim_end_matches('.').to_string());
            }
        }
    }
    None
}

pub fn reverse_ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(_) => String::new(), // v6 targets are rejected upstream
    }
}

async fn system_nameservers() -> Vec<String> {
    if let Ok(text) = tokio::fs::read_to_string("/etc/resolv.conf").await {
        for line in text.lines() {
            let line = line.trim();
            if let Some(ns) = line.strip_prefix("nameserver") {
                let ns = ns.trim();
                if !ns.is_empty() {
                    let with_port = if ns.contains(':') && !ns.starts_with('[') {
                        format!("[{ns}]:53")
                    } else {
                        format!("{ns}:53")
                    };
                    return vec![with_port];
                }
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ptr_query_against_local_dns_responder() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            // answer: same question + one PTR record "nas.example."
            let mut resp = buf[..n].to_vec();
            resp[2] = 0x81;
            resp[3] = 0x80;
            resp[7] = 1; // ANCOUNT
            let mut tail = Vec::new();
            tail.extend_from_slice(&[0xC0, 0x0C]); // ptr to qname
            tail.extend_from_slice(&[0, 12, 0, 1]); // PTR IN
            tail.extend_from_slice(&0u32.to_be_bytes());
            let rdlen_pos = tail.len();
            tail.extend_from_slice(&[0, 0]);
            let rd_start = tail.len();
            for l in ["nas", "example"] {
                tail.push(l.len() as u8);
                tail.extend_from_slice(l.as_bytes());
            }
            tail.push(0);
            let rdlen = tail.len() - rd_start;
            tail[rdlen_pos..rdlen_pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
            resp.extend_from_slice(&tail);
            sock.send_to(&resp, peer).await.unwrap();
        });
        let name = ptr_lookup("127.0.0.1".parse().unwrap(), &addr.to_string(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(name, "nas.example");
        server_task.await.unwrap();
    }

    #[test]
    fn reverse_name() {
        assert_eq!(
            reverse_ptr_name("192.0.2.5".parse().unwrap()),
            "5.2.0.192.in-addr.arpa"
        );
    }
}
