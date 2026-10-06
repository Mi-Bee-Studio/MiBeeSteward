//! SMB probe: SMB2 Negotiate on 445 (dialects 2.1/3.0/3.0.2/3.1.1), parse
//! the selected dialect (+OS via SMB1 fallback shape later). Evidence kind
//! `smb_negotiate` with dialect/os/port (Go probe/smb.go).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

pub struct SmbProbe;

const DIALECTS: [u16; 4] = [0x0210, 0x0300, 0x0302, 0x0311]; // 2.1, 3.0, 3.0.2, 3.1.1

pub fn dialect_name(d: u16) -> String {
    match d {
        0x0210 => "2.1".into(),
        0x0300 => "3.0".into(),
        0x0302 => "3.0.2".into(),
        0x0311 => "3.1.1".into(),
        0x0202 => "2.0.2".into(),
        other => format!("0x{other:04x}"),
    }
}

probe_impl!(SmbProbe, "active:smb", |ip: IpAddr, hint: &ProbeHint| async move {

        let port = 445u16;
        if !hint.port_spec.contains(&port) {
            return Vec::new();
        }
        let Some((dialect, os)) = negotiate(ip, port, Duration::from_secs(3)).await else {
            return Vec::new();
        };
        let mut e = ev("active:smb", "smb_negotiate", ip, 0.95);
        e.port = port as i64;
        e.protocol = "tcp".into();
        let mut rd = BTreeMap::new();
        rd.insert("dialect".into(), dialect_name(dialect));
        if let Some(os) = os {
            rd.insert("os".into(), os);
        }
        rd.insert("port".into(), port.to_string());
        e.raw_data = Some(rd);
        vec![e]
});

/// Build an SMB2 NEGOTIATE request inside NetBIOS session framing.
pub fn build_negotiate() -> Vec<u8> {
    let mut neg = Vec::new();
    neg.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    neg.extend_from_slice(&DIALECTS.len().to_le_bytes()); // DialectCount
    neg.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    neg.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    neg.extend_from_slice(&0x0200u16.to_le_bytes()); // Capabilities (SMB2.0.2+)
    neg.extend_from_slice(&[0x47, 0x50, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00]); // ClientGUID
    neg.extend_from_slice(&0u32.to_le_bytes()); // ClientStartTime
    for d in DIALECTS {
        neg.extend_from_slice(&d.to_le_bytes());
    }
    let mut header = vec![0xFE, 0x53, 0x4D, 0x42]; // ProtocolId SMB2
    header.extend_from_slice(&[0; 4]); // StructureSize(64)/CreditCharge... placeholder per spec
    // SMB2 header: Status(4) Command(2) CreditResponse(2) Flags(4) NextCommand(4)
    // MessageId(8) Reserved(4) TreeId(4) SessionId(8) Signature(16) = 64 bytes total
    header.extend_from_slice(&[0; 4]); // status
    header.extend_from_slice(&0u16.to_le_bytes()); // command = NEGOTIATE
    header.extend_from_slice(&1u16.to_le_bytes()); // credit response
    header.extend_from_slice(&0u32.to_le_bytes()); // flags
    header.extend_from_slice(&0u32.to_le_bytes()); // next command
    header.extend_from_slice(&0u64.to_le_bytes()); // message id
    header.extend_from_slice(&0u32.to_le_bytes()); // reserved
    header.extend_from_slice(&0u32.to_le_bytes()); // tree id
    header.extend_from_slice(&0u64.to_le_bytes()); // session id
    header.extend_from_slice(&[0; 16]); // signature
    debug_assert_eq!(header.len(), 64); // MS-SMB2 header incl. ProtocolId
    let mut msg = header;
    msg.extend_from_slice(&neg);
    // NetBISS session header: type 0x81? For direct TCP (445): 4-byte
    // length prefix, zero-extension.
    let mut out = Vec::with_capacity(msg.len() + 4);
    let len = msg.len() as u32;
    out.push(0);
    out.extend_from_slice(&(len as u16).to_be_bytes()[..1].to_vec());
    out.clear();
    out.push(0);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.extend_from_slice(&msg);
    out
}

async fn negotiate(ip: IpAddr, port: u16, timeout: Duration) -> Option<(u16, Option<String>)> {
    let addr = SocketAddr::new(ip, port);
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;
    s.write_all(&build_negotiate()).await.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, s.read(&mut buf)).await.ok()?.ok()?;
    parse_negotiate_response(&buf[..n])
}

/// Parse the SMB2 negotiate response: dialect in the fixed offset.
pub fn parse_negotiate_response(buf: &[u8]) -> Option<(u16, Option<String>)> {
    // 4-byte NBT length + FE SMB2 + 64B header; dialect at 4+64+4 = 72
    if buf.len() < 74 {
        return None;
    }
    if buf[4] != 0xFE {
        return None; // not SMB2 (SMB1 would start with 0xFF — dialect via flags2)
    }
    let dialect = u16::from_le_bytes([buf[4 + 64 + 4], buf[4 + 64 + 5]]);
    Some((dialect, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_packet_shape() {
        let pkt = build_negotiate();
        assert_eq!(&pkt[4..8], &[0xFE, 0x53, 0x4D, 0x42]);
        // NBT length prefix covers the message
        let declared = ((pkt[1] as usize) << 16) | ((pkt[2] as usize) << 8) | pkt[3] as usize;
        assert_eq!(declared, pkt.len() - 4);
    }

    #[test]
    fn parses_response_dialect() {
        let mut buf = vec![0u8; 128];
        buf[4] = 0xFE;
        // dialect 3.1.1 at offset 4+64+4 = 72
        buf[72] = 0x11;
        buf[73] = 0x03;
        let (d, os) = parse_negotiate_response(&buf).unwrap();
        assert_eq!(dialect_name(d), "3.1.1");
        assert!(os.is_none());
    }

    #[test]
    fn dialect_names() {
        assert_eq!(dialect_name(0x0210), "2.1");
        assert_eq!(dialect_name(0x0300), "3.0");
    }
}
