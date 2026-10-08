//! NetBIOS NBNS Node Status probe: unicast UDP 137, "*" query; parse the
//! node-name table for hostname + workgroup (Go probe/udp_discovery.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

pub struct NetbiosProbe;

probe_impl!(NetbiosProbe, "active:netbios", |ip: IpAddr, hint: &ProbeHint| async move {

        let Some((hostname, workgroup)) = node_status(ip, hint.timeout).await else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if !hostname.is_empty() {
            let mut e = ev("active:netbios", "netbios", ip, 0.9);
            let mut rd = BTreeMap::new();
            rd.insert("hostname".into(), hostname.clone());
            if !workgroup.is_empty() {
                rd.insert("workgroup".into(), workgroup.clone());
            }
            e.raw_data = Some(rd);
            e.port = 137;
            e.protocol = "udp".into();
            out.push(e);
            // second hostname-kind evidence for the workstation name
            let mut h = ev("active:netbios", "hostname", ip, 0.8);
            h.raw_data = Some(BTreeMap::from([("hostname".into(), hostname)]));
            out.push(h);
        }
        out
});

/// Build the NBSTAT query for name "*<suffix 0>" (RFC 1002 encoded).
pub fn build_node_status_query(trx: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(50);
    q.extend_from_slice(&trx.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // QNAME: level-1 encoding of "*" padded to 15 bytes + suffix 0x00
    let name_bytes = {
        let mut padded = [b' '; 15];
        padded[0] = b'*';
        let mut nb = [0u8; 32];
        for (i, b) in padded.iter().enumerate() {
            let hi = b >> 4;
            let lo = b & 0x0F;
            nb[i * 2] = b'A' + hi;
            nb[i * 2 + 1] = b'A' + lo;
        }
        nb.to_vec()
    };
    q.extend_from_slice(&[0x20]); // length 32
    q.extend_from_slice(&name_bytes);
    q.push(0x00); // suffix
    q.push(0x00); // scope
    q.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
    q
}

/// Parse a node status response: names table after the RR header.
/// Returns (hostname, workgroup). Robust to trailing statistics blocks.
pub fn parse_node_status(buf: &[u8]) -> Option<(String, String)> {
    // header 12 bytes + question encoded name (variable) + RR fields; the
    // practical route: find the RDLENGTH then the names count byte.
    // Walk: skip header, skip question (encoded name length byte + name +
    // suffix + scope), then RR name (often another encoded name)...
    // Simplification that matches real-world replies: search for the RR
    // NBSTAT signature (00 21 00 01 <ttl4> <rdlen2>) then parse the count.
    for i in 0..buf.len().saturating_sub(12) {
        if buf[i] == 0x00 && buf[i + 1] == 0x21 && buf[i + 2] == 0x00 && buf[i + 3] == 0x01 {
            let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
            let data_start = i + 10;
            let data_end = (data_start + rdlen).min(buf.len());
            let data = &buf[data_start..data_end];
            let Some(&count) = data.first() else { break };
            let mut hostname = String::new();
            let mut workgroup = String::new();
            let mut pos = 1;
            for _ in 0..count.min(64) {
                if pos + 18 > data.len() {
                    break;
                }
                let name = decode_nb_name(&data[pos..pos + 15]);
                let flags = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);
                pos += 18;
                if flags & 0x8000 != 0 {
                    // group name: the first one is the workgroup/domain
                    if workgroup.is_empty() {
                        workgroup = name;
                    }
                    continue;
                }
                if hostname.is_empty() {
                    hostname = name; // first unique name = workstation
                }
            }
            return Some((hostname, workgroup));
        }
    }
    None
}

fn decode_nb_name(raw: &[u8]) -> String {
    // names are space-padded ASCII directly in the node table
    let s = String::from_utf8_lossy(raw);
    s.trim_end_matches(' ').trim_end_matches('\0').to_string()
}

async fn node_status(ip: IpAddr, timeout: Duration) -> Option<(String, String)> {
    let addr = SocketAddr::new(ip, 137);
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let q = build_node_status_query(0x1337);
    sock.send_to(&q, addr).await.ok()?;
    let mut buf = [0u8; 1500];
    let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await else {
        return None;
    };
    parse_node_status(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_shape() {
        let q = build_node_status_query(0x1234);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(q[12], 32); // encoded name length
        // first level-1 pair encodes '*'
        assert_eq!(q[13], b'A' + 2); // '*'>>4 = 2
        assert_eq!(q[14], b'A' + 10); // '*'&0xF = 0xA
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x21, 0x00, 0x01]);
    }

    #[test]
    fn parses_names_table() {
        // header + minimal question + RR with 2 names
        let mut m = Vec::new();
        m.extend_from_slice(&[0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        m.push(32);
        m.extend_from_slice(&[b'A'; 32]);
        m.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]); // suffix, scope, NBSTAT IN
        m.extend_from_slice(&0u32.to_be_bytes()); // TTL
        let rdlen_pos = m.len();
        m.extend_from_slice(&[0, 0]);
        let rd_start = m.len();
        m.push(2); // two names
        let mut name1 = [b' '; 15];
        name1[..9].copy_from_slice(b"DESKTOP-9");
        m.extend_from_slice(&name1);
        m.push(0x00); // suffix
        m.extend_from_slice(&0x0400u16.to_be_bytes()); // workstation flag
        let mut name2 = [b' '; 15];
        name2[..4].copy_from_slice(b"WORK");
        m.extend_from_slice(&name2);
        m.push(0x00);
        m.extend_from_slice(&0x8080u16.to_be_bytes()); // group
        let rdlen = m.len() - rd_start;
        m[rdlen_pos..rdlen_pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
        let (host, wg) = parse_node_status(&m).unwrap();
        assert_eq!(host, "DESKTOP-9");
        assert_eq!(wg, "WORK");
    }
}
