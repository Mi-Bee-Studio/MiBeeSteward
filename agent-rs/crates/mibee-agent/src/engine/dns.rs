//! Minimal DNS codec: PTR query building + response parsing (name
//! compression, PTR/A/CNAME/TXT/SRV), shared by the rDNS and mDNS probes.
//! Wire-format only; no resolver crate.

pub fn build_ptr_query(qname: &str, id: u16, recursion_desired: bool) -> Vec<u8> {
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
    out.extend_from_slice(&12u16.to_be_bytes()); // QTYPE=PTR
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
    A(std::net::Ipv4Addr),
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
    let _flags = r.u16()?;
    let qdcount = r.u16()?;
    let ancount = r.u16()?;
    let nscount = r.u16()?;
    let arcount = r.u16()?;
    for _ in 0..qdcount {
        r.name(0)?;
        r.u16()?; // qtype
        r.u16()?; // qclass
    }
    let mut msg = Message { id, ..Default::default() };
    for i in 0..(ancount + nscount + arcount) {
        let name = r.name(0)?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let _ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let start = r.pos;
        let rdata = match rtype {
            12 => RData::Ptr(r.name(1)?), // compression allowed inside rdata
            1 if rdlen == 4 => {
                let a = r.u8()?;
                let b = r.u8()?;
                let c = r.u8()?;
                let d = r.u8()?;
                RData::A(std::net::Ipv4Addr::new(a, b, c, d))
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
}
