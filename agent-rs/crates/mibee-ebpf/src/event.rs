//! Ring-buffer event decoding — byte-exact port of the Go center decoder
//! (`internal/service/scannerv2/ebpf/event.go`). The binary layout mirrors
//! `struct event` in `bpf/tc_ingress.c` byte for byte:
//!
//! ```text
//! offset  size  field
//! 0       4     src_ip     (raw network-order bytes; read as LE u32)
//! 4       2     port       (LE u16)
//! 6       2     proto      (LE u16, IP protocol number)
//! 8       1     kind
//! 9       1     pad
//! 10      64    server[64]     (C string; DHCP vendor-class / TLS SNI /
//!                               ND sender IPv6 in [0:16])
//! 74      12    opt55_raw[12]  (DHCP parameter-request list raw bytes;
//!                               ARP/ND sender MAC in [0:6])
//! 86      32    name_raw[32]   (mDNS wire-format query name)
//! 118     1     opt55_len
//! 119     1     dhcp_type      (DHCP message type; ARP op; ND ICMPv6 type)
//! ```
//!
//! All string building happens here — the BPF program writes constant-index
//! bytes only. Decoding never panics on malformed input: truncated records
//! and unknown kinds yield `None`, which callers drop.

/// Ring-buffer record size, mirroring `EVENT_LEN` in the C program.
pub const EVENT_LEN: usize = 124;

// Kind constants — keep in sync with the enum in bpf/tc_ingress.c.
pub const KIND_SSH: u8 = 1;
pub const KIND_RTSP: u8 = 2;
pub const KIND_HTTP: u8 = 3;
pub const KIND_WS_DISCOVERY: u8 = 4;
pub const KIND_DHCP: u8 = 5;
pub const KIND_TLS_SNI: u8 = 6;
pub const KIND_MDNS: u8 = 7;
pub const KIND_SSDP: u8 = 8;
pub const KIND_ARP: u8 = 9;
pub const KIND_ND: u8 = 10;

/// What the BPF program saw. The discriminants mirror the wire byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ssh,
    Rtsp,
    Http,
    WsDiscovery,
    Dhcp,
    TlsSni,
    Mdns,
    Ssdp,
    /// ARP presence sighting (#497): a hard on-wire liveness fact.
    ArpSighting,
    /// NDP presence sighting (#497): MAC-keyed, carries no IPv4.
    NdSighting,
}

impl Kind {
    fn from_wire(b: u8) -> Option<Kind> {
        Some(match b {
            KIND_SSH => Kind::Ssh,
            KIND_RTSP => Kind::Rtsp,
            KIND_HTTP => Kind::Http,
            KIND_WS_DISCOVERY => Kind::WsDiscovery,
            KIND_DHCP => Kind::Dhcp,
            KIND_TLS_SNI => Kind::TlsSni,
            KIND_MDNS => Kind::Mdns,
            KIND_SSDP => Kind::Ssdp,
            KIND_ARP => Kind::ArpSighting,
            KIND_ND => Kind::NdSighting,
            _ => return None,
        })
    }

    /// Evidence kind string (Go parity: the classifier's vocabulary).
    pub fn evidence_kind(self) -> &'static str {
        match self {
            Kind::Ssh => "banner",
            Kind::Rtsp => "rtsp_banner",
            Kind::Http => "banner",
            Kind::WsDiscovery => "wsdiscovery",
            Kind::Dhcp => "dhcp",
            Kind::TlsSni => "tls_sni",
            Kind::Mdns => "mdns",
            Kind::Ssdp => "ssdp",
            Kind::ArpSighting => "arp_sighting",
            Kind::NdSighting => "nd_sighting",
        }
    }

    /// `service_hint` raw-data value (Go parity).
    pub fn service_hint(self) -> &'static str {
        match self {
            Kind::Ssh => "ssh",
            Kind::Rtsp => "rtsp",
            Kind::Http => "http",
            Kind::WsDiscovery => "onvif",
            Kind::Dhcp => "dhcp",
            Kind::TlsSni => "https",
            Kind::Mdns => "mdns",
            Kind::Ssdp => "ssdp",
            Kind::ArpSighting => "arp",
            Kind::NdSighting => "nd",
        }
    }

    /// DHCP carries vendor-class + parameter-list self-declaration and an
    /// ARP/ND sighting is a hard on-wire liveness fact from the sender itself
    /// (both 0.8, the same weight as the active mDNS/SSDP seeds); a TLS SNI
    /// is a somewhat weaker client-side hint; plain protocol presence stays
    /// corroborating.
    pub fn confidence(self) -> f64 {
        match self {
            Kind::Dhcp | Kind::ArpSighting | Kind::NdSighting => 0.8,
            Kind::TlsSni => 0.7,
            _ => 0.6,
        }
    }
}

/// One decoded ring-buffer record. Field-for-field the Go decoder's output
/// before it shapes `Evidence`; the agent-side adapter (mibee-agent
/// `ebpf_source`) performs that shaping so this crate stays
/// fingerprint-agnostic and dependency-free.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Event {
    pub kind: Option<Kind>,
    /// Dotted sender IPv4; empty for ND sightings (presence is MAC-keyed).
    pub ip: String,
    pub port: u16,
    /// "tcp" / "udp" / "ip:N"; "arp" and "icmpv6" for presence kinds.
    pub protocol: String,
    /// The server[64] slot as a C string (DHCP vendor-class, TLS SNI).
    pub server: String,
    /// DHCP parameter-request list as comma-joined decimal ("" when absent).
    pub opt55: String,
    /// DHCP message type; 0 = absent.
    pub msg_type: u8,
    /// mDNS query name decoded from the wire-format label run.
    pub query: String,
    /// ARP/ND sender MAC ("aa:bb:cc:dd:ee:ff"); "" for signature kinds.
    pub mac: String,
    /// ARP operation: true = request, false = reply.
    pub op_is_request: bool,
    /// ND sender IPv6 rendered canonically ("" for other kinds).
    pub ipv6: String,
    /// ND ICMPv6 type (133/135/136); 0 for other kinds.
    pub icmp6_type: u8,
}

impl Event {
    /// ARP/ND presence sightings are facts about the network, not service
    /// evidence — they route to the discovery channel, never into the
    /// evidence buffer (Go `routePassive` parity).
    pub fn is_presence(&self) -> bool {
        matches!(self.kind, Some(Kind::ArpSighting) | Some(Kind::NdSighting))
    }
}

/// Decode one ring-buffer record. `None` for truncated records and unknown
/// kinds (the Go decoder returns an empty Evidence there; `None` is the same
/// drop decision expressed in the type).
pub fn decode(b: &[u8]) -> Option<Event> {
    if b.len() < EVENT_LEN {
        return None;
    }
    let kind = Kind::from_wire(b[8])?;
    let server = trim_c_string(&b[10..74]);
    let mut ev = Event {
        kind: Some(kind),
        ip: ip_string(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        port: u16::from_le_bytes([b[4], b[5]]),
        protocol: proto_name(u16::from_le_bytes([b[6], b[7]])),
        server: server.clone(),
        ..Default::default()
    };
    match kind {
        Kind::Dhcp => {
            // vendor_class reuses the server slot (the C program writes the
            // option-60 string there); opt55 only when 1..=12 bytes present.
            ev.opt55 = opt55_joined(&b[74..74 + opt55_len(b[118])]);
            ev.msg_type = b[119];
        }
        Kind::Mdns => {
            ev.query = decode_dns_wire_name(&b[86..118]);
        }
        Kind::ArpSighting | Kind::NdSighting => {
            ev.protocol = if kind == Kind::ArpSighting {
                "arp"
            } else {
                "icmpv6"
            }
            .to_string();
            ev.mac = mac_string(&b[74..80]);
            if kind == Kind::ArpSighting {
                ev.op_is_request = b[119] == 1;
            } else {
                ev.ipv6 = ipv6_string(&b[10..26]);
                ev.icmp6_type = b[119];
                ev.ip = String::new(); // MAC-keyed; no IPv4 to report
            }
        }
        _ => {}
    }
    Some(ev)
}

/// Clamp the opt55 length byte to the 12-byte slot (Go parity: only 1..=12
/// bytes count as a present list).
fn opt55_len(raw: u8) -> usize {
    match raw {
        1..=12 => raw as usize,
        _ => 0,
    }
}

/// Render a DHCP parameter request list as comma-joined decimal — the
/// canonical form the fingerprint corpus matches on.
fn opt55_joined(b: &[u8]) -> String {
    b.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Render the 6 bytes of the MAC slot as aa:bb:cc:dd:ee:ff.
fn mac_string(b: &[u8]) -> String {
    b.iter()
        .map(|v| format!("{v:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Render the 16 raw bytes of the ND sender address; an all-zero capture
/// reads as "::" (the BPF read can only fail on truncated frames, which the
/// program drops before emitting).
fn ipv6_string(b: &[u8]) -> String {
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&b[..16]);
    std::net::Ipv6Addr::from(raw).to_string()
}

/// Render length-prefixed DNS labels (the wire format the BPF program
/// captures verbatim) as a dot-joined hostname. Rejects anything malformed:
/// label lengths > 63 (compression pointers live there) and truncation
/// without a terminating root label yield "".
fn decode_dns_wire_name(b: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let n = b[i] as usize;
        if n == 0 {
            return out;
        }
        if n > 63 || i + 1 + n > b.len() {
            return String::new();
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&b[i + 1..i + 1 + n]));
        i += 1 + n;
    }
    String::new()
}

fn trim_c_string(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// src_ip holds raw network-order bytes; the C side wrote them verbatim, so
/// the LE u32 read renders them in wire order (Go ipString parity).
fn ip_string(le: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        le as u8,
        (le >> 8) as u8,
        (le >> 16) as u8,
        (le >> 24) as u8
    )
}

/// Map the IP protocol number recorded by the BPF program.
fn proto_name(p: u16) -> String {
    match p {
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        _ => format!("ip:{p}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go sampleEvent parity: fill the header + server slot.
    fn sample_event(kind: u8, ip: u32, port: u16, proto: u16, server: &str) -> [u8; EVENT_LEN] {
        let mut b = [0u8; EVENT_LEN];
        b[0..4].copy_from_slice(&ip.to_le_bytes());
        b[4..6].copy_from_slice(&port.to_le_bytes());
        b[6..8].copy_from_slice(&proto.to_le_bytes());
        b[8] = kind;
        let bytes = server.as_bytes();
        b[10..10 + bytes.len()].copy_from_slice(bytes);
        b
    }

    /// Go mk() parity: full v4 layout (server/opt55/name/type slots).
    fn mk(
        kind: u8,
        ip: u32,
        port: u16,
        proto: u16,
        s: &str,
        opt55: &[u8],
        name: &[u8],
        t: u8,
    ) -> [u8; EVENT_LEN] {
        let mut b = sample_event(kind, ip, port, proto, s);
        b[74..74 + opt55.len()].copy_from_slice(opt55);
        b[86..86 + name.len()].copy_from_slice(name);
        b[118] = opt55.len() as u8;
        b[119] = t;
        b
    }

    /// Go presenceEvent parity: ARP/ND field mapping.
    fn presence_event(
        kind: u8,
        ip: u32,
        mac: &[u8; 6],
        ipv6: &[u8; 16],
        type_byte: u8,
        proto: u16,
    ) -> [u8; EVENT_LEN] {
        let mut b = sample_event(kind, ip, 0, proto, "");
        b[10..26].copy_from_slice(ipv6);
        b[74..80].copy_from_slice(mac);
        b[118] = 6;
        b[119] = type_byte;
        b
    }

    #[test]
    fn decodes_banner_kinds() {
        let cases = [
            (
                KIND_SSH,
                6u16,
                "OpenSSH_9.6p1",
                Kind::Ssh,
                "banner",
                "ssh",
                "tcp",
            ),
            (
                KIND_RTSP,
                6,
                "RTSP/1.0 200 OK",
                Kind::Rtsp,
                "rtsp_banner",
                "rtsp",
                "tcp",
            ),
            (
                KIND_HTTP,
                6,
                "HTTP/1.1 200 OK",
                Kind::Http,
                "banner",
                "http",
                "tcp",
            ),
            (
                KIND_WS_DISCOVERY,
                17,
                "",
                Kind::WsDiscovery,
                "wsdiscovery",
                "onvif",
                "udp",
            ),
        ];
        for (wire, proto, server, kind, ekind, hint, protocol) in cases {
            // src_ip as a little-endian u32, 0x0100A8C0 renders 192.168.0.1.
            let ev = decode(&sample_event(wire, 0x0100A8C0, 5555, proto, server)).unwrap();
            assert_eq!(ev.kind, Some(kind), "kind for wire {wire}");
            assert_eq!(ev.protocol, protocol);
            assert_eq!(kind.evidence_kind(), ekind);
            assert_eq!(kind.service_hint(), hint);
            assert_eq!(ev.ip, "192.168.0.1");
            assert_eq!(ev.port, 5555);
            assert_eq!(ev.server, server);
            assert_eq!(kind.confidence(), 0.6);
            assert!(!ev.is_presence());
        }
    }

    #[test]
    fn unknown_kind_and_truncated_yield_none() {
        assert!(decode(&sample_event(99, 0x0100A8C0, 5555, 6, "whatever")).is_none());
        assert!(decode(&[0u8; 8]).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn decodes_dhcp_self_declaration() {
        let ev = decode(&mk(
            KIND_DHCP,
            0x0100A8C0,
            68,
            17,
            "android-dhcp-13",
            &[1, 33, 3, 6, 15, 26, 28, 51, 58, 59],
            &[],
            1,
        ))
        .unwrap();
        assert_eq!(ev.kind, Some(Kind::Dhcp));
        assert_eq!(ev.server, "android-dhcp-13"); // vendor_class rides the server slot
        assert_eq!(ev.opt55, "1,33,3,6,15,26,28,51,58,59");
        assert_eq!(ev.msg_type, 1);
        assert_eq!(ev.protocol, "udp");
        assert_eq!(Kind::Dhcp.confidence(), 0.8);
    }

    #[test]
    fn dhcp_opt55_length_byte_gates_the_list() {
        // Go parity: only 1..=12 counts as a present list; 0, 13 or larger
        // (corrupt length byte) means the option is absent.
        let ev = decode(&mk(KIND_DHCP, 1, 68, 17, "vc", &[1, 3, 6], &[], 1)).unwrap();
        assert_eq!(ev.opt55, "1,3,6");
        let mut b = mk(KIND_DHCP, 1, 68, 17, "vc", &[1, 3, 6], &[], 1);
        b[118] = 13;
        let ev = decode(&b).unwrap();
        assert_eq!(ev.opt55, "");
        b[118] = 0;
        let ev = decode(&b).unwrap();
        assert_eq!(ev.opt55, "");
    }

    #[test]
    fn decodes_tls_sni() {
        let ev = decode(&mk(
            KIND_TLS_SNI,
            0x0100A8C0,
            443,
            6,
            "blog.mickeyzzc.tech",
            &[],
            &[],
            0,
        ))
        .unwrap();
        assert_eq!(ev.kind, Some(Kind::TlsSni));
        assert_eq!(ev.server, "blog.mickeyzzc.tech");
        assert_eq!(ev.protocol, "tcp");
        assert_eq!(Kind::TlsSni.confidence(), 0.7);
    }

    #[test]
    fn decodes_mdns_wire_name_and_rejects_compression() {
        let mut wire = vec![10u8];
        wire.extend_from_slice(b"rig-sensor");
        wire.push(4);
        wire.extend_from_slice(b"_tcp");
        wire.push(5);
        wire.extend_from_slice(b"local");
        let ev = decode(&mk(KIND_MDNS, 0x0100A8C0, 5353, 17, "", &[], &wire, 0)).unwrap();
        assert_eq!(ev.kind, Some(Kind::Mdns));
        assert_eq!(ev.query, "rig-sensor._tcp.local");
        // compression pointer byte (0xc0) is a malformed label length here
        let ev = decode(&mk(
            KIND_MDNS,
            0x0100A8C0,
            5353,
            17,
            "",
            &[],
            &[0xc0, 0x0c],
            0,
        ))
        .unwrap();
        assert_eq!(ev.query, "");
    }

    #[test]
    fn decodes_ssdp() {
        let ev = decode(&mk(KIND_SSDP, 0x0100A8C0, 1900, 17, "", &[], &[], 0)).unwrap();
        assert_eq!(ev.kind, Some(Kind::Ssdp));
        assert_eq!(ev.protocol, "udp");
    }

    #[test]
    fn decodes_arp_sighting() {
        // sender 192.168.0.50, MAC 02:81:48:4e:d5:99, op = request
        let ev = decode(&presence_event(
            KIND_ARP,
            0x3200A8C0,
            &[0x02, 0x81, 0x48, 0x4e, 0xd5, 0x99],
            &[0; 16],
            1,
            0,
        ))
        .unwrap();
        assert_eq!(ev.kind, Some(Kind::ArpSighting));
        assert_eq!(ev.ip, "192.168.0.50");
        assert_eq!(ev.protocol, "arp");
        assert_eq!(ev.mac, "02:81:48:4e:d5:99");
        assert!(ev.op_is_request);
        assert_eq!(Kind::ArpSighting.confidence(), 0.8);
        assert!(ev.is_presence());
        // op = reply
        let ev = decode(&presence_event(
            KIND_ARP,
            0x3200A8C0,
            &[2, 0x81, 0x48, 0x4e, 0xd5, 0x99],
            &[0; 16],
            2,
            0,
        ))
        .unwrap();
        assert!(!ev.op_is_request);
    }

    #[test]
    fn decodes_nd_sighting_without_ipv4() {
        let mut ipv6 = [0u8; 16];
        ipv6[0] = 0xfe;
        ipv6[1] = 0x80;
        ipv6[12] = 0x10;
        ipv6[13] = 0x1a;
        ipv6[14] = 0x20;
        ipv6[15] = 0x2b;
        let ev = decode(&presence_event(
            KIND_ND,
            0,
            &[0x02, 0x81, 0x48, 0x4e, 0xd5, 0x99],
            &ipv6,
            135,
            58,
        ))
        .unwrap();
        assert_eq!(ev.kind, Some(Kind::NdSighting));
        assert_eq!(ev.ipv6, "fe80::101a:202b");
        assert_eq!(ev.mac, "02:81:48:4e:d5:99");
        assert_eq!(ev.icmp6_type, 135);
        assert_eq!(ev.protocol, "icmpv6");
        assert_eq!(ev.ip, ""); // MAC-keyed presence, no IPv4
        assert!(ev.is_presence());
    }

    #[test]
    fn ip_and_proto_rendering() {
        // 0x0100007F as LE u32 renders the wire-order bytes 127.0.0.1.
        assert_eq!(ip_string(0x0100007F), "127.0.0.1");
        assert_eq!(ip_string(0), "0.0.0.0");
        assert_eq!(proto_name(6), "tcp");
        assert_eq!(proto_name(17), "udp");
        assert_eq!(proto_name(1), "ip:1");
    }
}
