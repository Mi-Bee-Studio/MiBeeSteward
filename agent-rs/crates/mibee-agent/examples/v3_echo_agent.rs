//! SNMPv3 USM echo agent — the Rust side of the gosnmp interop difftest.
//! Serves one credential (argv: port level auth priv, same vocabulary as
//! the Go agent's credential strings) over UDP on 127.0.0.1: answers the
//! RFC 3414 §4 discovery Report, then verifies + decrypts authenticated
//! GETs and replies with an authenticated/encrypted GetResponse carrying
//! fixed sysDescr/sysName values. One process serves any number of
//! exchanges; kill with Ctrl-C.

use mibee_agent::engine::probes::snmp_v3::{
    ber_tlv, decode_v3_message, decrypt_scoped_pdu, encode_oid, hex_to_bytes, minimal_uint,
    parse_scoped_pdu, AuthProtocol, PrivProtocol, SecurityLevel, V3Params, V3Session,
    ENCRYPTED_MARKER, MSG_FLAG_REPORTABLE,
};
use mibee_agent::engine::probes::SnmpV3Credential;
use tokio::net::UdpSocket;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: v3_echo_agent <port> <level> <auth> <priv>");
        std::process::exit(2);
    }
    let port: u16 = args[1].parse().expect("port");
    // The interop script passes gosnmp's protocol names; the credential
    // storage vocabulary uses empty strings for "not set" (Go parity).
    let auth_protocol = if args[3] == "NoAuth" { String::new() } else { args[3].clone() };
    let priv_protocol = if args[4] == "NoPriv" { String::new() } else { args[4].clone() };
    let cred = SnmpV3Credential {
        username: "admin".into(),
        security_level: args[2].clone(),
        auth_protocol,
        auth_passphrase: "authpass".into(),
        priv_protocol,
        priv_passphrase: "privpass".into(),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(serve(port, cred));
}

async fn serve(port: u16, cred: SnmpV3Credential) {
    let sock = UdpSocket::bind(("127.0.0.1", port)).await.expect("bind");
    eprintln!("v3_echo_agent listening on 127.0.0.1:{port}");
    let engine_id: Vec<u8> = b"\x80\x00\x9b\x99\x99".to_vec();
    let mut buf = vec![0u8; 8192];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        let Some(req) = decode_v3_message(&buf[..n]) else {
            eprintln!("agent: undecodable packet from {peer}");
            continue;
        };
        if req.engine_id.is_empty() {
            // RFC 3414 §4: report the authoritative engine values.
            let mut s = V3Session::new(blank(), engine_id.clone(), 3, 1234);
            let report = build_report(&mut s, req.req_id as i32);
            sock.send_to(&report, peer).await.ok();
            continue;
        }
        let params = match V3Params::from_credential(&cred) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("agent: bad credential: {e}");
                return;
            }
        };
        let mut agent = V3Session::new(params, engine_id.clone(), 3, 1234);
        let mut msg = match agent.decode(&buf[..n], 0, false) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("agent: dropping request from {peer}: {e}");
                continue;
            }
        };
        if let Some(marker) = msg.varbind_names.first().cloned() {
            if let Some(ct_hex) = marker.strip_prefix(ENCRYPTED_MARKER) {
                match hex_to_bytes(ct_hex).as_deref().map(|ct| (decrypt_scoped_pdu(&agent, &msg, ct), ct)) {
                    Some((Some(pt), _)) => {
                        msg.varbind_names.clear();
                        msg.varbinds.clear();
                        if parse_scoped_pdu(&pt, &mut msg).is_none() {
                            eprintln!("agent: scopedPDU parse failed");
                            continue;
                        }
                    }
                    _ => {
                        eprintln!("agent: decrypt failed");
                        continue;
                    }
                }
            }
        }
        eprintln!("agent: verified GET with {} varbinds", msg.varbind_names.len());
        let resp = build_response(&mut agent, msg.req_id as i32, &msg.varbind_names);
        sock.send_to(&resp, peer).await.ok();
    }
}

fn blank() -> V3Params {
    V3Params {
        level: SecurityLevel::NoAuthNoPriv,
        auth: AuthProtocol::NoAuth,
        auth_pass: String::new(),
        priv_: PrivProtocol::NoPriv,
        priv_pass: String::new(),
        username: String::new(),
    }
}

fn build_report(s: &mut V3Session, req_id: i32) -> Vec<u8> {
    let mut vb = encode_oid("1.3.6.1.6.3.15.1.1.4.0");
    ber_tlv(0x41, &[0], &mut vb); // Counter32 usmStatsUnknownEngineIDs.0
    let mut vbl = Vec::new();
    ber_tlv(0x30, &vb, &mut vbl);
    let mut vbl_seq = Vec::new();
    ber_tlv(0x30, &vbl, &mut vbl_seq);
    let mut pdu_body = Vec::new();
    ber_tlv(0x02, &minimal_uint(req_id as u64), &mut pdu_body);
    ber_tlv(0x02, &[0], &mut pdu_body);
    ber_tlv(0x02, &[0], &mut pdu_body);
    pdu_body.extend_from_slice(&vbl_seq);
    s.encode_message(0xA8, &pdu_body, MSG_FLAG_REPORTABLE, false)
}

fn build_response(s: &mut V3Session, req_id: i32, oids: &[String]) -> Vec<u8> {
    let mut vbl = Vec::new();
    for oid in oids {
        let mut vb = encode_oid(oid);
        let val: &[u8] = if oid == "1.3.6.1.2.1.1.1.0" {
            b"Linux v3-echo-agent 6.1"
        } else if oid == "1.3.6.1.2.1.1.5.0" {
            b"echohost"
        } else {
            b""
        };
        ber_tlv(0x04, val, &mut vb);
        ber_tlv(0x30, &vb, &mut vbl);
    }
    let mut vbl_seq = Vec::new();
    ber_tlv(0x30, &vbl, &mut vbl_seq);
    let mut pdu_body = Vec::new();
    ber_tlv(0x02, &minimal_uint(req_id as u64), &mut pdu_body);
    ber_tlv(0x02, &[0], &mut pdu_body);
    ber_tlv(0x02, &[0], &mut pdu_body);
    pdu_body.extend_from_slice(&vbl_seq);
    let flags = s.flags();
    s.encode_message(0xA2, &pdu_body, flags, false)
}
