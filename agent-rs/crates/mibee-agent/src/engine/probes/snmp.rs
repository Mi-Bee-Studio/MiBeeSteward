//! SNMP probe: one Get of the 8 system OIDs, v2c with v1 fallback (2
//! attempts per version, 200ms→400ms backoff); USM v3 when a credential is
//! bound. Hand-rolled BER — gosnmp parity for the Get path (Go probe/
//! snmp.go + snmp_conn.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint, SnmpV3Credential};

pub struct SnmpProbe;

/// The 8 system OIDs (Go probe/snmp.go oidVars).
pub const SYS_OIDS: [&str; 8] = [
    "1.3.6.1.2.1.1.1.0", // sysDescr
    "1.3.6.1.2.1.1.2.0", // sysObjectID
    "1.3.6.1.2.1.1.3.0", // sysUpTime
    "1.3.6.1.2.1.1.4.0", // sysContact
    "1.3.6.1.2.1.1.5.0", // sysName
    "1.3.6.1.2.1.1.6.0", // sysLocation
    "1.3.6.1.2.1.1.7.0", // sysServices
    "1.3.6.1.2.1.2.1.0", // ifNumber
];

const FIELD_NAMES: [&str; 8] = [
    "sys_descr",
    "sys_object_id",
    "sys_up_time",
    "sys_contact",
    "sys_name",
    "sys_location",
    "sys_services",
    "if_number",
];

probe_impl!(SnmpProbe, "active:snmp", |ip: IpAddr, hint: &ProbeHint| async move {

        let community = hint
            .community_override
            .as_deref()
            .unwrap_or(&hint.community);
        let Some(vars) = snmp_get_system(
            ip,
            hint.snmp_port,
            community,
            hint.timeout,
            hint.snmp_v3.clone(),
        )
        .await
        else {
            return Vec::new();
        };
        let mut rd = BTreeMap::new();
        for (i, val) in vars.iter().enumerate() {
            if let Some(v) = val {
                rd.insert(FIELD_NAMES[i].to_string(), v.clone());
            }
        }
        if rd.is_empty() {
            return Vec::new();
        }
        let version = match hint.snmp_v3 {
            Some(_) => "3",
            None => {
                // v2c succeeded or fell back to v1 — recorded by the caller
                // via snmp_version; default v2c here, refined below.
                "2c"
            }
        };
        rd.insert("snmp_version".into(), version.to_string());
        if let Some(up) = rd.get("sys_up_time") {
            if let Ok(ticks) = up.parse::<f64>() {
                rd.insert("uptime_seconds".into(), format!("{:.0}", ticks / 100.0));
            }
        }
        let mut e = ev("active:snmp", "snmp", ip, 0.95);
        e.port = 161;
        e.protocol = "udp".into();
        e.raw_data = Some(rd);
        vec![e]
});

/// Get the 8 system varbinds. A v3 credential collapses the ladder to
/// SNMPv3 only (Go probe/snmp.go: falling back to v2c/v1 would defeat the
/// point of a hardened target); otherwise v2c (2 attempts) then v1.
#[allow(clippy::too_many_arguments)]
pub async fn snmp_get_system(
    ip: IpAddr,
    port: u16,
    community: &str,
    timeout: Duration,
    v3: Option<SnmpV3Credential>,
) -> Option<Vec<Option<String>>> {
    let addr = SocketAddr::new(ip, port);
    if let Some(cred) = v3 {
        return super::snmp_v3::v3_get(addr, &cred, timeout, &SYS_OIDS).await.ok();
    }
    for (version, community) in [(1u8, community.to_string()), (0u8, community.to_string())] {
        let mut backoff = Duration::from_millis(200);
        for _ in 0..2 {
            if let Some(vars) = snmp_get_attempt(addr, version, &community, timeout).await {
                return Some(vars);
            }
            tokio::time::sleep(backoff).await;
            backoff *= 2;
        }
    }
    None
}

async fn snmp_get_attempt(
    addr: SocketAddr,
    version_byte: u8, // 0 = v1, 1 = v2c
    community: &str,
    timeout: Duration,
) -> Option<Vec<Option<String>>> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let req_id = (std::process::id() as u32).wrapping_mul(7919) & 0x7FFFFF;
    let pkt = build_get_request(version_byte, community, req_id as i32, &SYS_OIDS);
    sock.send_to(&pkt, addr).await.ok()?;
    let mut buf = [0u8; 4096];
    let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await else {
        return None;
    };
    parse_get_response(&buf[..n], req_id as i32)
}

// ---------- BER ----------

fn ber_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
    }
}

fn ber_tlv(tag: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    ber_len(body.len(), out);
    out.extend_from_slice(body);
}

pub(crate) fn encode_oid(oid: &str) -> Vec<u8> {
    let parts: Vec<u64> = oid.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    let mut body = Vec::new();
    body.push((parts[0] * 40 + parts[1]) as u8);
    for &p in &parts[2..] {
        if p < 128 {
            body.push(p as u8);
        } else {
            let mut stack = Vec::new();
            let mut v = p;
            stack.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                stack.push(((v & 0x7F) as u8) | 0x80);
                v >>= 7;
            }
            stack.reverse();
            body.extend_from_slice(&stack);
        }
    }
    let mut out = Vec::new();
    ber_tlv(0x06, &body, &mut out);
    out
}

pub fn build_get_request(version: u8, community: &str, req_id: i32, oids: &[&str]) -> Vec<u8> {
    // msg VERSION + community + PDU(GetRequest [0xA0])
    let mut varbinds = Vec::new();
    for oid in oids {
        let mut vb = encode_oid(oid);
        // value = NULL (05 00)
        ber_tlv(0x05, &[], &mut vb);
        ber_tlv(0x30, &vb, &mut varbinds);
    }
    let mut varbind_list = Vec::new();
    ber_tlv(0x30, &varbinds, &mut varbind_list);

    let mut pdu_body = Vec::new();
    let int = |v: i32, out: &mut Vec<u8>| {
        let bytes = v.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
        let slice = &bytes[first..];
        let needs_pad = slice.first().map(|b| b & 0x80 != 0).unwrap_or(false);
        let mut body = Vec::new();
        if needs_pad {
            body.push(0);
        }
        body.extend_from_slice(slice);
        ber_tlv(0x02, &body, out);
    };
    int(req_id, &mut pdu_body);
    int(0, &mut pdu_body); // error-status
    int(0, &mut pdu_body); // error-index
    pdu_body.extend_from_slice(&varbind_list);
    let mut pdu = Vec::new();
    ber_tlv(0xA0, &pdu_body, &mut pdu);

    let mut msg_body = Vec::new();
    int(version as i32, &mut msg_body);
    ber_tlv(0x04, community.as_bytes(), &mut msg_body);
    msg_body.extend_from_slice(&pdu);
    let mut msg = Vec::new();
    ber_tlv(0x30, &msg_body, &mut msg);
    msg
}

// ---------- GETNEXT walk (Go probe/snmp_arp.go: gosnmp Walk = GetNext loop) ----------

/// One walked varbind: full dotted OID, BER value tag, raw value bytes.
/// Raw bytes (not decoded strings) because table values are binary — the
/// ARP table's PhysAddress is 6 raw octets that must not pass through a
/// UTF-8 lossy conversion.
#[derive(Debug, Clone, PartialEq)]
pub struct WalkVarbind {
    pub oid: String,
    pub tag: u8,
    pub value: Vec<u8>,
}

/// Build a single-OID GetNextRequest (PDU tag 0xA1).
pub fn build_getnext_request(version: u8, community: &str, req_id: i32, oid: &str) -> Vec<u8> {
    let mut vb = encode_oid(oid);
    ber_tlv(0x05, &[], &mut vb);
    let mut varbinds = Vec::new();
    ber_tlv(0x30, &vb, &mut varbinds);
    let mut varbind_list = Vec::new();
    ber_tlv(0x30, &varbinds, &mut varbind_list);

    let mut pdu_body = Vec::new();
    let int = |v: i32, out: &mut Vec<u8>| {
        let bytes = v.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
        let slice = &bytes[first..];
        let needs_pad = slice.first().map(|b| b & 0x80 != 0).unwrap_or(false);
        let mut body = Vec::new();
        if needs_pad {
            body.push(0);
        }
        body.extend_from_slice(slice);
        ber_tlv(0x02, &body, out);
    };
    int(req_id, &mut pdu_body);
    int(0, &mut pdu_body); // error-status
    int(0, &mut pdu_body); // error-index
    pdu_body.extend_from_slice(&varbind_list);
    let mut pdu = Vec::new();
    ber_tlv(0xA1, &pdu_body, &mut pdu);

    let mut msg_body = Vec::new();
    int(version as i32, &mut msg_body);
    ber_tlv(0x04, community.as_bytes(), &mut msg_body);
    msg_body.extend_from_slice(&pdu);
    let mut msg = Vec::new();
    ber_tlv(0x30, &msg_body, &mut msg);
    msg
}

/// Parse a GetResponse/GetNextResponse into raw varbinds plus the
/// error-status (2 = noSuchName, the v1 end-of-table signal).
pub fn parse_walk_response(buf: &[u8], expect_req_id: i32) -> Option<(u8, Vec<WalkVarbind>)> {
    let mut top = BerReader { buf, pos: 0 };
    let (seq_tag, msg) = top.tlv()?;
    if seq_tag != 0x30 {
        return None;
    }
    let mut r = BerReader { buf: msg, pos: 0 };
    let (_t_version, _ver) = r.tlv()?;
    let (_t_comm, _comm) = r.tlv()?;
    let (pdu_tag, pdu) = r.tlv()?;
    if !(0xA0..=0xA2).contains(&pdu_tag) {
        return None;
    }
    let mut p = BerReader { buf: pdu, pos: 0 };
    let (_t, id_body) = p.tlv()?;
    if decode_ber_int(id_body)? as i32 != expect_req_id {
        return None;
    }
    let (_t, err_status) = p.tlv()?;
    let err = decode_ber_int(err_status)?;
    let (_t, _err_idx) = p.tlv()?;
    let (_t, vbl) = p.tlv()?;
    let mut v = BerReader { buf: vbl, pos: 0 };
    let mut out = Vec::new();
    while let Some((tag, vb)) = v.tlv() {
        if tag != 0x30 {
            return None;
        }
        let mut vb_r = BerReader { buf: vb, pos: 0 };
        let (_t, oid) = vb_r.tlv()?;
        let (vt, val) = vb_r.tlv()?;
        out.push(WalkVarbind {
            oid: oid_to_string(oid),
            tag: vt,
            value: val.to_vec(),
        });
    }
    Some((err.clamp(0, 255) as u8, out))
}

/// Plain v2c Get returning RAW varbind values (tag + bytes) — the L2 MIB
/// probes need binary values (bridge addresses) the string-decoding Get
/// path would mangle. One attempt, no ladder (dead hosts cost one timeout,
/// not four).
pub(crate) async fn v2c_get_raw(
    addr: SocketAddr,
    community: &str,
    timeout: Duration,
    oids: &[&str],
) -> Option<Vec<(u8, Vec<u8>)>> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let req_id = (std::process::id() as u32).wrapping_mul(15485863) & 0x7FFFFF;
    let pkt = build_get_request(1, community, req_id as i32, oids);
    let reply = match udp_exchange_raw(&sock, addr, &pkt, timeout).await {
        Some(r) => Some(r),
        None => udp_exchange_raw(&sock, addr, &pkt, timeout).await,
    };
    let (err, vbs) = parse_walk_response(&reply?, req_id as i32)?;
    if err != 0 {
        return None;
    }
    Some(vbs.into_iter().map(|vb| (vb.tag, vb.value)).collect())
}

/// Component-wise OID prefix test ("1.3.6.2" must not match "1.3.6.22").
pub fn oid_starts_with(oid: &str, prefix: &str) -> bool {
    let mut a = oid.split('.');
    let mut b = prefix.split('.');
    loop {
        match (b.next(), a.next()) {
            (None, _) => return true,
            (Some(p), Some(o)) => {
                if p != o {
                    return false;
                }
            }
            (Some(_), None) => return false,
        }
    }
}

/// v2c GetNext walk of a table column: one persistent socket, GetNext from
/// the root until the returned OID leaves the subtree (v2c end-of-table) or
/// noSuchName (v1 end). One retransmit per exchange (gosnmp Retries=1
/// parity, Go walkRouterARPTableHint). Bound at 1024 rows.
pub async fn v2c_walk(
    addr: SocketAddr,
    community: &str,
    timeout: Duration,
    root_oid: &str,
) -> Option<Vec<WalkVarbind>> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let mut req_id = (std::process::id() as u32).wrapping_mul(104729) & 0x7FFFFF;
    let mut next = root_oid.to_string();
    let mut out = Vec::new();
    for _ in 0..1024 {
        let pkt = build_getnext_request(1, community, req_id as i32, &next);
        // one retransmit on silence (gosnmp Retries=1)
        let reply = match udp_exchange_raw(&sock, addr, &pkt, timeout).await {
            Some(r) => Some(r),
            None => udp_exchange_raw(&sock, addr, &pkt, timeout).await,
        };
        let (err_status, vbs) = parse_walk_response(&reply?, req_id as i32)?;
        req_id = req_id.wrapping_add(1) & 0x7FFFFF;
        if err_status == 2 {
            break; // v1 noSuchName: past the table end
        }
        let vb = vbs.first()?; // GetNext returns exactly one varbind
        if !oid_starts_with(&vb.oid, root_oid) {
            break; // next lexical OID is outside the walked subtree
        }
        next = vb.oid.clone();
        out.push(vb.clone());
    }
    Some(out)
}

/// One raw UDP exchange on an existing socket (walk iteration).
async fn udp_exchange_raw(
    sock: &tokio::net::UdpSocket,
    addr: SocketAddr,
    pkt: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    sock.send_to(pkt, addr).await.ok()?;
    let mut buf = vec![0u8; 65535];
    let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await else {
        return None;
    };
    buf.truncate(n);
    Some(buf)
}

/// Shared helpers for scripted-SNMP-agent tests (visible to sibling probe
/// test modules within the same crate-test build).
#[cfg(test)]
pub mod test_support {
    /// Component-wise dotted-OID ordering (string compare is wrong:
    /// "2.192" vs "2.9").
    pub fn cmp_oid(a: &str, b: &str) -> std::cmp::Ordering {
        let mut ai = a.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        let mut bi = b.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
        loop {
            match (ai.next(), bi.next()) {
                (None, None) => return std::cmp::Ordering::Equal,
                (None, Some(_)) => return std::cmp::Ordering::Less,
                (Some(_), None) => return std::cmp::Ordering::Greater,
                (Some(x), Some(y)) => match x.cmp(&y) {
                    std::cmp::Ordering::Equal => continue,
                    o => return o,
                },
            }
        }
    }

    /// Extract (request-id, first varbind OID) from a request packet.
    pub fn request_id_and_oid(req: &[u8]) -> Option<(i32, String)> {
        let mut r = super::BerReader { buf: req, pos: 0 };
        let (_, msg) = r.tlv()?;
        let mut m = super::BerReader { buf: msg, pos: 0 };
        let (_, _v) = m.tlv()?;
        let (_, _c) = m.tlv()?;
        let (_, pdu) = m.tlv()?;
        let mut p = super::BerReader { buf: pdu, pos: 0 };
        let (_, idb) = p.tlv()?;
        let req_id = super::decode_ber_int(idb)? as i32;
        let _ = p.tlv()?;
        let _ = p.tlv()?;
        let (_, vbl) = p.tlv()?;
        let mut v = super::BerReader { buf: vbl, pos: 0 };
        let (_, vb) = v.tlv()?;
        let mut vr = super::BerReader { buf: vb, pos: 0 };
        let (_, oid) = vr.tlv()?;
        Some((req_id, super::oid_to_string(oid)))
    }

    /// (request-id, PDU tag, first varbind OID) from a request packet.
    pub fn request_pdu(req: &[u8]) -> Option<(i32, u8, String)> {
        let mut r = super::BerReader { buf: req, pos: 0 };
        let (_, msg) = r.tlv()?;
        let mut m = super::BerReader { buf: msg, pos: 0 };
        let (_, _v) = m.tlv()?;
        let (_, _c) = m.tlv()?;
        let (pdu_tag, pdu) = m.tlv()?;
        let mut p = super::BerReader { buf: pdu, pos: 0 };
        let (_, idb) = p.tlv()?;
        let req_id = super::decode_ber_int(idb)? as i32;
        let _ = p.tlv()?;
        let _ = p.tlv()?;
        let (_, vbl) = p.tlv()?;
        let mut v = super::BerReader { buf: vbl, pos: 0 };
        let (_, vb) = v.tlv()?;
        let mut vr = super::BerReader { buf: vb, pos: 0 };
        let (_, oid) = vr.tlv()?;
        Some((req_id, pdu_tag, super::oid_to_string(oid)))
    }

    /// GetResponse with error-status 2 (noSuchName) — end-of-table.
    fn walk_err_reply(req_id: i32) -> Vec<u8> {
        let mut pdu_body = Vec::new();
        ber_tlv_small(0x02, &(req_id as u32).to_be_bytes()[1..], &mut pdu_body);
        ber_tlv_small(0x02, &[2], &mut pdu_body); // error-status
        ber_tlv_small(0x02, &[1], &mut pdu_body); // error-index
        let mut vbl_seq = Vec::new();
        ber_tlv_small(0x30, &[], &mut vbl_seq);
        pdu_body.extend_from_slice(&vbl_seq);
        let mut pdu = Vec::new();
        ber_tlv_small(0xA2, &pdu_body, &mut pdu);
        let mut msg_body = Vec::new();
        ber_tlv_small(0x02, &[1], &mut msg_body);
        ber_tlv_small(0x04, b"public", &mut msg_body);
        msg_body.extend_from_slice(&pdu);
        let mut msg = Vec::new();
        ber_tlv_small(0x30, &msg_body, &mut msg);
        msg
    }

    /// Canned 8-varbind GetResponse for the sys* OIDs.
    fn sys_get_reply(req_id: i32) -> Vec<u8> {
        let values: [(&str, u8, Vec<u8>); 8] = [
            ("1.3.6.1.2.1.1.1.0", 0x04, b"Linux fake-sw 6.1".to_vec()),
            ("1.3.6.1.2.1.1.2.0", 0x06, vec![43, 6, 1, 4, 1, 9, 1, 0x85, 0x38]),
            ("1.3.6.1.2.1.1.3.0", 0x43, vec![0x01, 0x86, 0xA0]),
            ("1.3.6.1.2.1.1.4.0", 0x04, Vec::new()),
            ("1.3.6.1.2.1.1.5.0", 0x04, b"fake-sw".to_vec()),
            ("1.3.6.1.2.1.1.6.0", 0x04, Vec::new()),
            ("1.3.6.1.2.1.1.7.0", 0x02, vec![72]),
            ("1.3.6.1.2.1.2.1.0", 0x02, vec![8]),
        ];
        let mut vbl = Vec::new();
        for (oid, vt, val) in values {
            let mut vb = super::encode_oid(oid);
            ber_tlv_small(vt, &val, &mut vb);
            ber_tlv_small(0x30, &vb, &mut vbl);
        }
        let mut vbl_seq = Vec::new();
        ber_tlv_small(0x30, &vbl, &mut vbl_seq);
        let mut pdu_body = Vec::new();
        ber_tlv_small(0x02, &(req_id as u32).to_be_bytes()[1..], &mut pdu_body);
        ber_tlv_small(0x02, &[0], &mut pdu_body);
        ber_tlv_small(0x02, &[0], &mut pdu_body);
        pdu_body.extend_from_slice(&vbl_seq);
        let mut pdu = Vec::new();
        ber_tlv_small(0xA2, &pdu_body, &mut pdu);
        let mut msg_body = Vec::new();
        ber_tlv_small(0x02, &[1], &mut msg_body);
        ber_tlv_small(0x04, b"public", &mut msg_body);
        msg_body.extend_from_slice(&pdu);
        let mut msg = Vec::new();
        ber_tlv_small(0x30, &msg_body, &mut msg);
        msg
    }

    fn ber_tlv_small(tag: u8, body: &[u8], out: &mut Vec<u8>) {
        out.push(tag);
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else if body.len() < 256 {
            out.extend_from_slice(&[0x81, body.len() as u8]);
        } else {
            out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
        }
        out.extend_from_slice(body);
    }

    /// Scripted SNMP agent for walk tests: answers every GetNext with the
    /// lexically-next row (each row carries its own value tag, so integer
    /// and octet-string columns both work), and answers the 8-OID sys* Get
    /// (PDU 0xA0) with canned system varbinds — that is what opens the
    /// engine's SNMP gate. `end_oid` must be greater than every row yet
    /// OUTSIDE the walked column — that is how a real agent terminates a
    /// walk (the client stops on the prefix mismatch). Bounded at 128
    /// exchanges.
    pub async fn spawn_fake_router(
        rows: Vec<(String, Vec<u8>)>,
        end_oid: String,
    ) -> std::net::SocketAddr {
        spawn_fake_router_typed(
            rows.into_iter().map(|(o, v)| (o, 0x04, v)).collect(),
            end_oid,
        )
        .await
    }

    /// Tagged-value variant of spawn_fake_router: rows are (oid, BER value
    /// tag, value bytes) — use 0x02 for integer columns.
    pub async fn spawn_fake_router_typed(
        rows: Vec<(String, u8, Vec<u8>)>,
        end_oid: String,
    ) -> std::net::SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut all = rows.clone();
            all.push((end_oid, 0x02, vec![0]));
            for _ in 0..128 {
                let mut buf = [0u8; 1024];
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
                let Some((req_id, pdu_tag, oid)) = request_pdu(&buf[..n]) else { return };
                if pdu_tag == 0xA0 && oid == super::SYS_OIDS[0] {
                    // the sys* Get: canned 8 varbinds (sysDescr first)
                    let reply = sys_get_reply(req_id);
                    if sock.send_to(&reply, peer).await.is_err() {
                        return;
                    }
                    continue;
                }
                // lexically-next row, scanning in sorted order so the FIRST
                // greater match is the smallest one
                let mut sorted = all.clone();
                sorted.sort_by(|a, b| cmp_oid(&a.0, &b.0));
                let next = sorted
                    .iter()
                    .find(|(o, _, _)| cmp_oid(o, &oid) == std::cmp::Ordering::Greater);
                let Some((noid, vtag, val)) = next else {
                    // past every scripted row: answer like a real agent at
                    // end-of-MIB-view (v1-style noSuchName, err-status 2) so
                    // the task KEEPS SERVING other probes — a plain `return`
                    // here would kill the fake for every concurrent walker.
                    let reply = walk_err_reply(req_id);
                    if sock.send_to(&reply, peer).await.is_err() {
                        return;
                    }
                    continue;
                };
                let mut vb = super::encode_oid(noid);
                ber_tlv_small(*vtag, val, &mut vb);
                let mut vbl = Vec::new();
                ber_tlv_small(0x30, &vb, &mut vbl);
                let mut vbl_seq = Vec::new();
                ber_tlv_small(0x30, &vbl, &mut vbl_seq);
                let mut pdu_body = Vec::new();
                ber_tlv_small(0x02, &(req_id as u32).to_be_bytes()[1..], &mut pdu_body);
                ber_tlv_small(0x02, &[0], &mut pdu_body);
                ber_tlv_small(0x02, &[0], &mut pdu_body);
                pdu_body.extend_from_slice(&vbl_seq);
                let mut pdu = Vec::new();
                ber_tlv_small(0xA2, &pdu_body, &mut pdu);
                let mut msg_body = Vec::new();
                ber_tlv_small(0x02, &[1], &mut msg_body);
                ber_tlv_small(0x04, b"public", &mut msg_body);
                msg_body.extend_from_slice(&pdu);
                let mut msg = Vec::new();
                ber_tlv_small(0x30, &msg_body, &mut msg);
                if sock.send_to(&msg, peer).await.is_err() {
                    return;
                }
            }
        });
        addr
    }
}

struct BerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.buf.get(self.pos)?;
        self.pos += 1;
        let first = *self.buf.get(self.pos)?;
        self.pos += 1;
        let len = if first < 128 {
            first as usize
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 4 {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *self.buf.get(self.pos)? as usize;
                self.pos += 1;
            }
            l
        };
        let start = self.pos;
        self.pos = self.pos.checked_add(len)?;
        if self.pos > self.buf.len() {
            return None;
        }
        Some((tag, &self.buf[start..start + len]))
    }
}

fn oid_to_string(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let mut parts = vec![(body[0] / 40).to_string(), (body[0] % 40).to_string()];
    let mut v: u64 = 0;
    for &b in &body[1..] {
        v = (v << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            parts.push(v.to_string());
            v = 0;
        }
    }
    parts.join(".")
}

/// Parse a GetResponse: verify request id and return values per bound OID
/// order (strings for OCTET STRING/OID, ints decoded decimal).
pub fn parse_get_response(buf: &[u8], expect_req_id: i32) -> Option<Vec<Option<String>>> {
    let mut top = BerReader { buf, pos: 0 };
    let (seq_tag, msg) = top.tlv()?;
    if seq_tag != 0x30 {
        return None;
    }
    let mut r = BerReader { buf: msg, pos: 0 };
    let (_t_version, _ver) = r.tlv()?;
    let (_t_comm, _comm) = r.tlv()?;
    let (pdu_tag, pdu) = r.tlv()?;
    if !(0xA0..=0xA2).contains(&pdu_tag) {
        return None;
    }
    let mut p = BerReader { buf: pdu, pos: 0 };
    let (_t, id_body) = p.tlv()?;
    let got_id = decode_ber_int(id_body)? as i32;
    if got_id != expect_req_id {
        return None;
    }
    let (_t, err_status) = p.tlv()?;
    if decode_ber_int(err_status)? != 0 {
        return None;
    }
    let (_t, _err_idx) = p.tlv()?;
    let (_t, vbl) = p.tlv()?;
    let mut v = BerReader { buf: vbl, pos: 0 };
    let mut out = Vec::new();
    while let Some((tag, vb)) = v.tlv() {
        if tag != 0x30 {
            return None;
        }
        let mut vb_r = BerReader { buf: vb, pos: 0 };
        let (_t, _oid) = vb_r.tlv()?;
        let (vt, val) = vb_r.tlv()?;
        let decoded = match vt {
            0x04 => Some(String::from_utf8_lossy(val).into_owned()), // OCTET STRING
            0x06 => Some(oid_to_string(val)),
            0x02 | 0x0A => decode_ber_int(val).map(|i| i.to_string()),
            0x05 | 0x80 => None, // NULL / noSuchObject-ish
            0x40 => Some(decode_ber_ip(val)), // IpAddress
            0x43 => decode_ber_ticks(val).map(|t| t.to_string()), // TimeTicks
            _ => Some(hex_of(val)),
        };
        out.push(decoded);
    }
    Some(out)
}

fn decode_ber_int(body: &[u8]) -> Option<i64> {
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    let mut v = if body[0] & 0x80 != 0 { -1i64 } else { 0 };
    for &b in body {
        v = (v << 8) | b as i64;
    }
    Some(v)
}

fn decode_ber_ip(body: &[u8]) -> String {
    if body.len() == 4 {
        format!("{}.{}.{}.{}", body[0], body[1], body[2], body[3])
    } else {
        hex_of(body)
    }
}

fn decode_ber_ticks(body: &[u8]) -> Option<u64> {
    decode_ber_int(body).map(|v| v as u64)
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_v2c_get_request() {
        let pkt = build_get_request(1, "public", 42, &SYS_OIDS);
        assert_eq!(pkt[0], 0x30);
        // smoke: contains the community and 8 NULL varbinds (8x 05 00)
        let nulls = pkt.windows(2).filter(|w| w == &[0x05, 0x00]).count();
        assert!(nulls >= 8, "{nulls}"); // 8 varbind NULLs (OID bytes can match too)
        assert!(pkt.windows(6).any(|w| w == b"public"));
    }

    #[test]
    fn builds_valid_getnext_request() {
        let pkt = build_getnext_request(1, "public", 7, "1.3.6.1.2.1.4.22.1.2");
        // PDU tag 0xA1 appears exactly once (the GetNext PDU)
        assert_eq!(pkt.iter().filter(|b| **b == 0xA1).count(), 1);
        assert!(pkt.windows(6).any(|w| w == b"public"));
    }

    #[test]
    fn oid_prefix_is_componentwise() {
        assert!(oid_starts_with("1.3.6.1.2.1.4.22.1.2.2.192.0.2.1", "1.3.6.1.2.1.4.22.1.2"));
        assert!(oid_starts_with("1.3.6.1.2.1.4.22.1.2", "1.3.6.1.2.1.4.22.1.2"));
        assert!(!oid_starts_with("1.3.6.2.1", "1.3.6.22")); // string-prefix trap
        assert!(!oid_starts_with("1.3.6.1.2.1.4.22.1.3.1", "1.3.6.1.2.1.4.22.1.2"));
    }

    #[test]
    fn walk_response_roundtrip_keeps_raw_octets() {
        // A GetResponse carrying a 6-octet PhysAddress: must stay raw bytes,
        // not pass through UTF-8 lossy decoding.
        let mut vb = encode_oid("1.3.6.1.2.1.4.22.1.2.2.192.0.2.1");
        ber_tlv(0x04, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], &mut vb);
        let mut vbl = Vec::new();
        ber_tlv(0x30, &vb, &mut vbl);
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &vbl, &mut vbl_seq);
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &[9], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        pdu_body.extend_from_slice(&vbl_seq);
        let mut pdu = Vec::new();
        ber_tlv(0xA2, &pdu_body, &mut pdu);
        let mut msg_body = Vec::new();
        ber_tlv(0x02, &[1], &mut msg_body);
        ber_tlv(0x04, b"public", &mut msg_body);
        msg_body.extend_from_slice(&pdu);
        let mut msg = Vec::new();
        ber_tlv(0x30, &msg_body, &mut msg);
        let (err, vbs) = parse_walk_response(&msg, 9).unwrap();
        assert_eq!(err, 0);
        assert_eq!(vbs.len(), 1);
        assert_eq!(vbs[0].oid, "1.3.6.1.2.1.4.22.1.2.2.192.0.2.1");
        assert_eq!(vbs[0].tag, 0x04);
        assert_eq!(vbs[0].value, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        assert!(parse_walk_response(&msg, 8).is_none(), "req id mismatch");
    }

    #[tokio::test]
    async fn v2c_walk_against_scripted_table() {
        // Scripted SNMP agent: answers GetNext with the lexically-next row;
        // the last reply leaves the walked subtree, which must stop the walk.
        let root = "1.3.6.1.2.1.4.22.1.2";
        let rows: Vec<(String, Vec<u8>)> = vec![
            (
                format!("{root}.2.192.0.2.1"),
                vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01],
            ),
            (
                format!("{root}.2.192.0.2.2"),
                vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02],
            ),
            ("1.3.6.1.2.1.4.22.1.3.1".to_string(), vec![5]), // outside the column
        ];
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let server_rows = rows.clone();
        let server = tokio::spawn(async move {
            for _ in 0..8 {
                let mut buf = [0u8; 1024];
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
                let Some((req_id, oid)) = request_id_and_oid(&buf[..n]) else { return };
                // first row strictly lexically-greater (component-wise)
                let next = server_rows.iter().find(|(o, _)| cmp_oid(o, &oid) == std::cmp::Ordering::Greater);
                let Some((noid, val)) = next else { return };
                let reply = walk_reply(req_id, noid, &val);
                if sock.send_to(&reply, peer).await.is_err() {
                    return;
                }
            }
        });
        let vbs = v2c_walk(addr, "public", Duration::from_secs(2), root)
            .await
            .expect("walk completes");
        assert_eq!(vbs.len(), 2, "stops at the out-of-subtree row");
        assert_eq!(vbs[0].oid, format!("{root}.2.192.0.2.1"));
        assert_eq!(vbs[0].value, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        assert_eq!(vbs[1].oid, format!("{root}.2.192.0.2.2"));
        assert_eq!(vbs[1].value, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
        server.abort();
    }

    fn cmp_oid(a: &str, b: &str) -> std::cmp::Ordering {
        test_support::cmp_oid(a, b)
    }

    fn request_id_and_oid(req: &[u8]) -> Option<(i32, String)> {
        test_support::request_id_and_oid(req)
    }

    fn walk_reply(req_id: i32, oid: &str, val: &[u8]) -> Vec<u8> {
        let mut vb = encode_oid(oid);
        ber_tlv(0x04, val, &mut vb);
        let mut vbl = Vec::new();
        ber_tlv(0x30, &vb, &mut vbl);
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &vbl, &mut vbl_seq);
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &(req_id as u32).to_be_bytes()[1..], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        pdu_body.extend_from_slice(&vbl_seq);
        let mut pdu = Vec::new();
        ber_tlv(0xA2, &pdu_body, &mut pdu);
        let mut msg_body = Vec::new();
        ber_tlv(0x02, &[1], &mut msg_body);
        ber_tlv(0x04, b"public", &mut msg_body);
        msg_body.extend_from_slice(&pdu);
        let mut msg = Vec::new();
        ber_tlv(0x30, &msg_body, &mut msg);
        msg
    }

    #[test]
    fn roundtrips_response_parse() {
        // Build a canned GetResponse with BER by hand.
        let mut vbl = Vec::new();
        let values: [(&str, u8, &[u8]); 3] = [
            ("1.3.6.1.2.1.1.1.0", 0x04, b"Linux rpi 6.1"),
            ("1.3.6.1.2.1.1.5.0", 0x04, b"rpi3b"),
            ("1.3.6.1.2.1.1.7.0", 0x02, &[72]),
        ];
        for (oid, vt, val) in values {
            let mut vb = encode_oid(oid);
            ber_tlv(vt, val, &mut vb);
            ber_tlv(0x30, &vb, &mut vbl);
        }
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &vbl, &mut vbl_seq);
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &[42], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        pdu_body.extend_from_slice(&vbl_seq);
        let mut pdu = Vec::new();
        ber_tlv(0xA2, &pdu_body, &mut pdu); // GetResponse
        let mut msg_body = Vec::new();
        ber_tlv(0x02, &[1], &mut msg_body);
        ber_tlv(0x04, b"public", &mut msg_body);
        msg_body.extend_from_slice(&pdu);
        let mut msg = Vec::new();
        ber_tlv(0x30, &msg_body, &mut msg);
        let vars = parse_get_response(&msg, 42).unwrap();
        assert_eq!(vars[0].as_deref(), Some("Linux rpi 6.1"));
        assert_eq!(vars[1].as_deref(), Some("rpi3b"));
        assert_eq!(vars[2].as_deref(), Some("72"));
        assert!(parse_get_response(&msg, 7).is_none(), "request id mismatch");
    }

    #[tokio::test]
    async fn snmp_get_against_local_responder() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            // extract req id from the packet: find the PDU integer — simply
            // reflect using our own builder layout: id is the first INTEGER
            // after community; locate by parsing.
            let vars = parse_request_for_reply(&buf[..n]);
            sock.send_to(&vars, peer).await.unwrap();
        });
        let vars = snmp_get_system(
            "127.0.0.1".parse().unwrap(),
            addr.port(),
            "public",
            Duration::from_secs(2),
            None,
        )
        .await
        .unwrap();
        assert_eq!(vars.len(), 8);
        assert_eq!(vars[0].as_deref(), Some("Linux test 6.1"));
        assert_eq!(vars[4].as_deref(), Some("testhost"));
        server.await.unwrap();
    }

    /// Test responder: parse the request id/OIDs and emit sysDescr+sysName.
    fn parse_request_for_reply(req: &[u8]) -> Vec<u8> {
        let mut r = BerReader { buf: req, pos: 0 };
        let (_, msg) = r.tlv().unwrap();
        let mut m = BerReader { buf: msg, pos: 0 };
        let (_, _v) = m.tlv().unwrap();
        let (_, _c) = m.tlv().unwrap();
        let (_, pdu) = m.tlv().unwrap();
        let mut p = BerReader { buf: pdu, pos: 0 };
        let (_, idb) = p.tlv().unwrap();
        let req_id = decode_ber_int(idb).unwrap() as i32;
        let mut vbl = Vec::new();
        for (oid, vt, val) in [
            ("1.3.6.1.2.1.1.1.0", 0x04u8, &b"Linux test 6.1"[..]),
            ("1.3.6.1.2.1.1.2.0", 0x06, &[43, 6, 1, 4, 1, 9, 1, 0x85, 0x38][..]),
            ("1.3.6.1.2.1.1.3.0", 0x43, &[0x01, 0x86, 0xA0]),
            ("1.3.6.1.2.1.1.4.0", 0x04, b""),
            ("1.3.6.1.2.1.1.5.0", 0x04, &b"testhost"[..]),
            ("1.3.6.1.2.1.1.6.0", 0x04, b""),
            ("1.3.6.1.2.1.1.7.0", 0x02, &[72]),
            ("1.3.6.1.2.1.2.1.0", 0x02, &[2]),
        ] {
            let mut vb = encode_oid(oid);
            ber_tlv(vt, val, &mut vb);
            ber_tlv(0x30, &vb, &mut vbl);
        }
        let mut vbl_seq = Vec::new();
        ber_tlv(0x30, &vbl, &mut vbl_seq);
        let mut pdu_body = Vec::new();
        ber_tlv(0x02, &(req_id as u32).to_be_bytes()[1..], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        ber_tlv(0x02, &[0], &mut pdu_body);
        pdu_body.extend_from_slice(&vbl_seq);
        let mut pdu = Vec::new();
        ber_tlv(0xA2, &pdu_body, &mut pdu);
        let mut msg_body = Vec::new();
        ber_tlv(0x02, &[1], &mut msg_body);
        ber_tlv(0x04, b"public", &mut msg_body);
        msg_body.extend_from_slice(&pdu);
        let mut msg = Vec::new();
        ber_tlv(0x30, &msg_body, &mut msg);
        msg
    }
}
