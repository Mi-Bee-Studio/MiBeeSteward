//! ICMP probe: unprivileged UDP-datagram ICMP echo (Go pro-bing
//! SetPrivileged(false) semantics). Linux only — requires
//! net.ipv4.ping_group_range to include the agent's GID (or root). On
//! non-Linux builds this is a no-op (tests run on Windows).

use std::net::IpAddr;

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

pub struct IcmpProbe;

probe_impl!(IcmpProbe, "active:icmp", |ip: IpAddr, hint: &ProbeHint| async move { #[cfg(target_os = "linux")]
        {
            if let Some(rtt_ms) = datagram_ping_once(ip, hint.timeout).await {
                let mut e = ev("active:icmp", "echo", ip, 1.0);
                e.raw_data = Some(
                    [("rtt_ms".to_string(), format!("{rtt_ms}"))].into_iter().collect(),
                );
                return vec![e];
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ip, hint);
        }
        Vec::new() });

#[cfg(target_os = "linux")]
pub(crate) async fn datagram_ping_once(ip: IpAddr, timeout: std::time::Duration) -> Option<u64> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if ip.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::ICMPV4)).ok()?;
    sock.set_nonblocking(true).ok()?;
    let std_sock: std::net::UdpSocket = sock.into();
    let sock = tokio::net::UdpSocket::from_std(std_sock).ok()?;
    // The kernel derives the echo id from the socket's local port.
    let ident: u16 = (std::process::id() & 0xFFFF) as u16;
    let payload: [u8; 16] = [0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    let mut pkt = vec![8u8, 0, (ident >> 8) as u8, (ident & 0xFF) as u8, 0, 1, 0, 1];
    pkt.extend_from_slice(&payload);
    let target = std::net::SocketAddr::new(ip, ident);
    sock.send_to(&pkt, target).await.ok()?;
    let start = std::time::Instant::now();
    let mut buf = [0u8; 2048];
    loop {
        let remain = timeout.saturating_sub(start.elapsed());
        if remain.is_zero() {
            return None;
        }
        let Ok(Ok((n, _))) = tokio::time::timeout(remain, sock.recv_from(&mut buf)).await else {
            return None;
        };
        // With SOCK_DGRAM ICMP the kernel strips the outer IP header and
        // rewrites id/port; match on echo-reply type + seq + payload marker.
        if n >= 16 && buf[0] == 0 && buf[1] == 0 && buf[6..8] == pkt[6..8] && buf[8..16] == payload[..8] {
            return Some(start.elapsed().as_millis() as u64);
        }
    }
}
