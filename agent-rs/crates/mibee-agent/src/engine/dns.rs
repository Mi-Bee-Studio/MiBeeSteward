//! Minimal DNS codec: query building (PTR + the prober's A/AAAA/CNAME/TXT)
//! and response parsing (name compression, PTR/A/AAAA/CNAME/TXT/SRV),
//! shared by the rDNS and mDNS probes and the prober's dns module (#605).
//! Wire-format only; no resolver crate.

pub fn build_ptr_query(qname: &str, id: u16, recursion_desired: bool) -> Vec<u8> {
    build_query(qname, 12, id, recursion_desired)
}

/// Generic query builder: qtype 1=A, 28=AAAA, 5=CNAME, 16=TXT, 12=PTR.
pub fn build_query(qname: &str, qtype: u16, id: u16, recursion_desired: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(qname.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    // QR=0 OPCODE=0 AA=0 TC=0 RD(recursion)
    out.push(if recursion_desired { 0x01 } else { 0x00 });
    out.push(0x00);
    // QDCOUNT=1
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(qname, &mut out);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    out
}

/// Encode a dotted name as DNS label sequence (no compression on write).
pub fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
}

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    Ptr(String),
    Cname(String),
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Txt(Vec<String>),
    Srv { prio: u16, weight: u16, port: u16, target: String },
    Other(u16),
}

#[derive(Debug, Clone)]
pub struct RR {
    pub name: String,
    pub rtype: u16,
    pub rdata: RData,
}

#[derive(Debug, Clone, Default)]
pub struct Message {
    pub id: u16,
    /// Response code (flags & 0x000F): 0 = NOERROR, 3 = NXDOMAIN.
    pub rcode: u8,
    pub answers: Vec<RR>,
    pub additional: Vec<RR>,
}

#[derive(Debug)]
pub struct DnsError(pub String);

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dns: {}", self.0)
    }
}

/// One UDP query round-trip against an explicit resolver: send, wait with a
/// deadline, parse, verify the transaction id. The prober's dns module
/// (#605) uses this for pinned resolvers (egress differential) and the
/// system nameserver alike. rcode is the caller's to interpret.
///
/// #715: a single-shot UDP query loses the whole probe to one dropped
/// packet, and the affected host's upstream drops UDP/53 per-packet at
/// 50–87% inside minute-scale clusters (same box: TCP/53 99.9%, so the path
/// itself is fine). Up to 3 attempts inside the caller's budget — same
/// socket (stable 5-tuple), fresh transaction id per attempt so a late
/// reply to an earlier attempt can never satisfy a later one. Center
/// parity: its RetryProber does the same 1+2 ladder.
pub async fn udp_query(
    addr: std::net::SocketAddr,
    qname: &str,
    qtype: u16,
    timeout: std::time::Duration,
) -> Result<Message, String> {
    const ATTEMPTS: u32 = 3;
    let per_attempt = (timeout / ATTEMPTS).max(std::time::Duration::from_millis(50));
    let sock = tokio::net::UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
        .await
        .map_err(|e| e.to_string())?;
    sock.connect(addr).await.map_err(|e| e.to_string())?;
    let base = (std::process::id() as u16).wrapping_mul(31) ^ qname.len() as u16;
    let mut buf = vec![0u8; 1500];
    let mut last_err = String::new();
    for attempt in 0..ATTEMPTS {
        let id = base ^ (attempt as u16).wrapping_mul(0x9E37);
        let q = build_query(qname, qtype, id, true);
        if let Err(e) = sock.send(&q).await {
            last_err = e.to_string();
            continue;
        }
        match tokio::time::timeout(per_attempt, sock.recv(&mut buf)).await {
            Err(_) => {
                last_err = "i/o timeout".to_string();
                continue;
            }
            Ok(Err(e)) => {
                last_err = e.to_string();
                continue;
            }
            Ok(Ok(n)) => {
                let msg = match parse_message(&buf[..n]) {
                    Ok(m) => m,
                    Err(e) => {
                        last_err = e.0;
                        continue;
                    }
                };
                if msg.id != id {
                    // A stray/late reply for another attempt (or someone
                    // else's query): retransmit with a fresh id.
                    last_err = "mismatched dns transaction id".to_string();
                    continue;
                }
                return Ok(msg);
            }
        }
    }
    Err(last_err)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, DnsError> {
        let b = *self.buf.get(self.pos).ok_or(DnsError(format!("truncated at {}", self.pos)))?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16, DnsError> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok(hi << 8 | lo)
    }
    fn u32(&mut self) -> Result<u32, DnsError> {
        let a = self.u16()? as u32;
        let b = self.u16()? as u32;
        Ok(a << 16 | b)
    }
    /// Read a (possibly compressed) name; guards pointer loops.
    fn name(&mut self, depth: usize) -> Result<String, DnsError> {
        if depth > 8 {
            return Err(DnsError("compression loop".into()));
        }
        let mut labels: Vec<String> = Vec::new();
        let mut jumped = false;
        let mut return_pos = 0usize;
        loop {
            let len = self.u8()?;
            match len {
                0 => break,
                0xC0..=0xFF => {
                    if jumped {
                        return Err(DnsError("double pointer".into()));
                    }
                    let ptr = ((len & 0x3F) as usize) << 8 | self.u8()? as usize;
                    return_pos = self.pos;
                    self.pos = ptr;
                    jumped = true;
                }
                _ => {
                    let end = self.pos + len as usize;
                    if end > self.buf.len() {
                        return Err(DnsError(format!("label overruns at {}", self.pos)));
                    }
                    labels.push(String::from_utf8_lossy(&self.buf[self.pos..end]).into_owned());
                    self.pos = end;
                }
            }
        }
        if jumped {
            self.pos = return_pos;
        }
        Ok(labels.join("."))
    }
}

pub fn parse_message(buf: &[u8]) -> Result<Message, DnsError> {
    let mut r = Reader { buf, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let qdcount = r.u16()?;
    let ancount = r.u16()?;
    let nscount = r.u16()?;
    let arcount = r.u16()?;
    for _ in 0..qdcount {
        r.name(0)?;
        r.u16()?; // qtype
        r.u16()?; // qclass
    }
    let mut msg = Message { id, rcode: (flags & 0x000F) as u8, ..Default::default() };
    for i in 0..(ancount + nscount + arcount) {
        let name = r.name(0)?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let _ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let start = r.pos;
        let rdata = match rtype {
            12 => RData::Ptr(r.name(1)?), // compression allowed inside rdata
            5 => RData::Cname(r.name(1)?),
            1 if rdlen == 4 => {
                let a = r.u8()?;
                let b = r.u8()?;
                let c = r.u8()?;
                let d = r.u8()?;
                RData::A(std::net::Ipv4Addr::new(a, b, c, d))
            }
            28 if rdlen == 16 => {
                let mut o = [0u8; 16];
                for b in o.iter_mut() {
                    *b = r.u8()?;
                }
                RData::Aaaa(std::net::Ipv6Addr::from(o))
            }
            16 => {
                // one or more length-prefixed character-strings
                let end = start + rdlen;
                let mut strs = Vec::new();
                while r.pos < end {
                    let n = r.u8()? as usize;
                    let s_end = (r.pos + n).min(end);
                    strs.push(String::from_utf8_lossy(&buf[r.pos..s_end]).into_owned());
                    r.pos = s_end;
                }
                RData::Txt(strs)
            }
            33 => {
                let prio = r.u16()?;
                let weight = r.u16()?;
                let port = r.u16()?;
                let target = r.name(1)?;
                RData::Srv { prio, weight, port, target }
            }
            _ => RData::Other(rtype),
        };
        // RDLENGTH boundary discipline (PTR/TXT parsing may consume exactly;
        // anything else fast-forwards).
        if r.pos > start + rdlen {
            return Err(DnsError(format!("rdata overrun type {rtype}")));
        }
        r.pos = start + rdlen;
        let rr = RR { name, rtype, rdata };
        if i < ancount {
            msg.answers.push(rr);
        } else {
            msg.additional.push(rr);
        }
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip_shape() {
        let q = build_ptr_query("5.2.0.192.in-addr.arpa", 0xBEEF, true);
        assert_eq!(&q[..2], &[0xBE, 0xEF]);
        assert_eq!(q[2], 0x01); // RD
        // QNAME labels for 5.2.0.192.in-addr.arpa
        let labels_start = 12;
        assert_eq!(q[labels_start], 1);
        assert_eq!(&q[labels_start + 1..labels_start + 2], b"5");
        // QTYPE PTR / QCLASS IN at the tail
        let n = q.len();
        assert_eq!(&q[n - 4..], &[0, 12, 0, 1]);
    }

    /// A real-shaped PTR answer with name compression.
    #[test]
    fn parses_ptr_answer_with_compression() {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes());
        m.extend_from_slice(&[0x81, 0x80]); // QR RD RA
        m.extend_from_slice(&1u16.to_be_bytes()); // qd
        m.extend_from_slice(&1u16.to_be_bytes()); // an
        m.extend_from_slice(&[0, 0, 0, 0]);
        // question: 5.2.0.192.in-addr.arpa IN PTR
        for l in ["5", "2", "0", "192", "in-addr", "arpa"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 12, 0, 1]);
        // answer: pointer to qname (0xC00C), PTR, IN, ttl 300, rdlen, name
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&[0, 12, 0, 1]);
        m.extend_from_slice(&300u32.to_be_bytes());
        // rdata: "host" "example" "com" then a compression pointer back to "arpa"
        let rdlen_pos = m.len();
        m.extend_from_slice(&[0, 0]); // placeholder
        let rd_start = m.len();
        for l in ["host", "example"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0xC0, 30]); // pointer to the "arpa" label (qname: 12+2+2+2+4+8=30)
        let rdlen = m.len() - rd_start;
        m[rdlen_pos..rdlen_pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
        let msg = parse_message(&m).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.answers.len(), 1);
        match &msg.answers[0].rdata {
            RData::Ptr(name) => assert_eq!(name, "host.example.arpa"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn txt_and_srv_parse() {
        // answer section with a TXT then SRV (mDNS-style, no question)
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&[0x84, 0x00]);
        m.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 0]);
        // TXT for _ssh._tcp.local
        for l in ["_ssh", "_tcp", "local"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 16, 0x80, 0x01, 0, 0, 0x11, 0]); // TXT cache-flush, ttl 4500
        m.extend_from_slice(&[0, 13]); // rdlen 13
        m.push(5);
        m.extend_from_slice(b"model=X6A"); // 5+8=13? 5 means len 5 -> "model" only... build precisely:
        let _ = m.split_off(m.len());
        // simpler: rebuild with exact strings
        let mut m = Vec::new();
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&[0x84, 0x00]);
        m.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 0]);
        for l in ["_ssh", "_tcp", "local"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 16, 0x80, 0x01]);
        m.extend_from_slice(&4500u32.to_be_bytes());
        let rdlen_pos = m.len();
        m.extend_from_slice(&[0, 0]);
        let rd_start = m.len();
        m.push(10);
        m.extend_from_slice(b"model=X6A1"); // len byte 10 + 10 bytes
        let rdlen = m.len() - rd_start;
        m[rdlen_pos..rdlen_pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
        // SRV
        for l in ["nanopineo", "_ssh", "_tcp", "local"] {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 33, 0x80, 0x01]);
        m.extend_from_slice(&120u32.to_be_bytes());
        let rdlen_pos = m.len();
        m.extend_from_slice(&[0, 0]);
        let rd_start = m.len();
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&22u16.to_be_bytes());
        encode_name("nanopineo.local", &mut m);
        let rdlen = m.len() - rd_start;
        m[rdlen_pos..rdlen_pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
        let msg = parse_message(&m).unwrap();
        assert_eq!(msg.answers.len(), 2);
        match &msg.answers[0].rdata {
            RData::Txt(v) => assert_eq!(v, &["model=X6A1".to_string()]),
            o => panic!("{o:?}"),
        }
        match &msg.answers[1].rdata {
            RData::Srv { port, target, .. } => {
                assert_eq!(*port, 22);
                assert!(target.starts_with("nanopineo."), "{target}");
            }
            o => panic!("{o:?}"),
        }
    }

    /// #715: a resolver that drops the first queries and then answers must
    /// be satisfied by a retransmit inside the same budget — the reply
    /// carries the retry attempt's transaction id.
    #[tokio::test]
    async fn udp_query_retransmits_through_packet_loss() {
        let srv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr: std::net::SocketAddr = srv.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let seen_c = std::sync::Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = srv.recv_from(&mut buf).await else { return };
                let seq = seen_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if seq < 2 {
                    continue; // drop the first two queries outright
                }
                // Echo the request header (so the id matches whatever
                // attempt is asking) with QR set; counts stay as sent.
                let mut resp = buf[..n].to_vec();
                resp[2] |= 0x80;
                let _ = srv.send_to(&resp, from).await;
            }
        });
        let msg = udp_query(addr, "example.com", 1, std::time::Duration::from_millis(1500))
            .await
            .expect("retransmit must recover from two dropped queries");
        assert_eq!(msg.answers.len(), 0);
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 3, "exactly three queries hit the wire");
    }

    /// #715: when everything is dropped the budget-guarded ladder surfaces
    /// the timeout error, not a hang.
    #[tokio::test]
    async fn udp_query_all_dropped_times_out() {
        let srv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr: std::net::SocketAddr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((_, _)) = srv.recv_from(&mut buf).await {}
        });
        let started = std::time::Instant::now();
        let err = udp_query(addr, "example.com", 1, std::time::Duration::from_millis(300))
            .await
            .expect_err("all-dropped must fail");
        assert!(err.contains("i/o timeout"), "err = {err}");
        // The whole ladder stays inside (roughly) the caller's budget.
        assert!(started.elapsed() < std::time::Duration::from_millis(1500));
    }
}
