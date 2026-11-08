//! Agent-side zero-privilege path tracer (#719) — a semantic port of the
//! center's `probeext/trace_linux.go` ("Go + Rust 各一份，行为一致"):
//!
//! - TCP connect: per-TTL nonblocking connect to the service port with
//!   IP_TTL + IP_RECVERR; Time-Exceeded arrives on the error queue. The
//!   source port is fixed per target (SO_REUSEADDR, hash-derived) so every
//!   attempt presents the same 5-tuple to ECMP hashing. The error queue is
//!   drained before every send, bounding the late-TE race to one per-hop
//!   window.
//! - ICMP ping socket: one SOCK_DGRAM ICMP socket per trace, IP_TTL set per
//!   attempt, seq carries the TTL; replies and the error queue share the
//!   socket (IP_RECVTTL cmsg gives the reply TTL).
//!
//! Linux-only (unprivileged ping sockets + IP_RECVERR); other targets get a
//! clean error result. The whole walk runs in spawn_blocking — it is a
//! sequence of ppoll-bounded syscalls, not async I/O.

use crate::wire::{PathHopReport, PathSampleReport, ProbeTargetSpec};

pub struct Tracer {
    pub max_ttl: i64,
    pub per_hop_ms: i64,
}

/// One trace's raw outcome (pre-report shaping).
#[derive(Debug, Clone, Default)]
pub struct TraceResult {
    pub method: String,
    pub dst_ip: String,
    pub hops: Vec<TraceHop>,
    pub end_state: String, // reached | max_ttl | error
    pub reached_ttl: i64,
    pub reply_ttl: i64,
    pub err: String,
}

#[derive(Debug, Clone, Default)]
pub struct TraceHop {
    pub ttl: i64,
    pub ip: String,
    pub ms: f64,
    pub reply_ttl: i64,
}

impl Tracer {
    pub fn new(max_ttl: i64, per_hop_ms: i64) -> Self {
        Tracer {
            max_ttl: if max_ttl > 0 { max_ttl } else { 30 },
            per_hop_ms: if per_hop_ms > 0 { per_hop_ms } else { 500 },
        }
    }

    /// Resolve host and walk the path ("auto" = tcp when port > 0, else
    /// icmp — mirrors the center's method choice).
    pub async fn trace_host(&self, host: &str, port: i64, method: &str) -> TraceResult {
        let method = if method.is_empty() || method == "auto" {
            if port > 0 {
                "tcp"
            } else {
                "icmp"
            }
        } else {
            method
        };
        let dst = match resolve_ipv4(host).await {
            Some(ip) => ip,
            None => {
                return TraceResult {
                    method: method.to_string(),
                    end_state: "error".into(),
                    err: format!("resolve {host}: no IPv4 answer"),
                    ..Default::default()
                }
            }
        };
        let (max_ttl, per_hop) = (self.max_ttl, self.per_hop_ms);
        let port_eff = if method == "tcp" && port <= 0 {
            80
        } else {
            port
        };
        // fn pointer: 'static + Send into spawn_blocking without cloning the
        // method decision.
        let walk: fn([u8; 4], i64, i64, i64) -> TraceResult = if method == "tcp" {
            imp::trace_tcp
        } else {
            imp::trace_icmp
        };
        tokio::task::spawn_blocking(move || walk(dst, port_eff, max_ttl, per_hop))
            .await
            .unwrap_or_else(|e| TraceResult {
                method: method.to_string(),
                end_state: "error".into(),
                err: format!("trace task: {e}"),
                ..Default::default()
            })
    }
}

async fn resolve_ipv4(host: &str) -> Option<[u8; 4]> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host.as_str(), 0)
            .to_socket_addrs()
            .ok()?
            .find_map(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => Some(v4.octets()),
                _ => None,
            })
    })
    .await
    .ok()
    .flatten()
}

/// host:port derivation from a probe spec (Go hostPortForTrace parity):
/// http/https URLs give host + scheme port (explicit port honored), tls/tcp
/// are host:port, icmp/dns give host + 0 (ICMP method).
pub fn host_port_for_trace(module: &str, target: &str) -> (String, i64) {
    match module {
        "http" => {
            if let Ok(u) = reqwest::Url::parse(target) {
                if u.host_str().is_some() {
                    let port = match u.port() {
                        Some(p) => p as i64,
                        None if u.scheme() == "https" => 443,
                        None => 80,
                    };
                    return (u.host_str().unwrap_or("").to_string(), port);
                }
            }
            let bare = target
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            (bare.to_string(), 80)
        }
        "tls" | "tcp" => match target.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(0)),
            None => (target.to_string(), 0),
        },
        _ => (target.to_string(), 0),
    }
}

/// Defense-in-depth reserved-address gate (#719): the plan itself comes from
/// CRUD-validated targets, but the tracer additionally refuses hard-reserved
/// IP literals (loopback/link-local/multicast/unspecified/documentation/
/// benchmark). Private ranges stay traceable — LAN targets are a legitimate
/// (if non-default) configuration.
pub fn trace_host_allowed(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return true; // hostnames resolve through the validated probe path
    };
    if ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    match ip.octets() {
        [192, 0, _, _] => false,
        [198, 18..=19, _, _] => false,
        [198, 51, 100, _] => false,
        [203, 0, 113, _] => false,
        _ => true,
    }
}

/// Trace one plan spec and shape the wire report. Never fails: broken specs
/// become stored error samples, matching the center's traceTarget.
pub async fn trace_spec(
    tracer: &Tracer,
    spec: &ProbeTargetSpec,
    trigger: &str,
) -> PathSampleReport {
    let mut report = PathSampleReport {
        target_id: spec.id,
        target_name: spec.name.clone(),
        trigger: trigger.to_string(),
        traced_at: crate::wire::now_rfc3339(),
        ..Default::default()
    };
    let (host, port) = host_port_for_trace(&spec.module, &spec.target);
    if host.is_empty() {
        report.end_state = "error".into();
        report.err = "cannot derive host from target".into();
        return report;
    }
    if !trace_host_allowed(&host) {
        report.end_state = "error".into();
        report.err = "reserved target refused".into();
        return report;
    }
    let res = tracer.trace_host(&host, port, "auto").await;
    report.method = res.method;
    report.resolved_ip = res.dst_ip;
    report.end_state = res.end_state;
    report.reached_ttl = res.reached_ttl;
    report.reply_ttl = res.reply_ttl;
    report.err = res.err;
    report.hops = res
        .hops
        .iter()
        .map(|h| PathHopReport {
            ttl: h.ttl,
            ip: h.ip.clone(),
            ms: h.ms,
        })
        .collect();
    report.visible_hops = report.hops.iter().filter(|h| !h.ip.is_empty()).count() as i64;
    report
}

/// Stable source port per (dst, port) so every TTL attempt of one target
/// hashes into the same ECMP bucket (Go fixedPort parity).
fn fixed_port(dst: [u8; 4], port: u16) -> u16 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([
        dst[0],
        dst[1],
        dst[2],
        dst[3],
        (port >> 8) as u8,
        (port & 0xFF) as u8,
    ]);
    let d = h.finalize();
    40000 + u16::from_be_bytes([d[0], d[1]]) % 20000
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    const POLLIN: i16 = libc::POLLIN;
    const POLLOUT: i16 = libc::POLLOUT;
    const POLLERR: i16 = libc::POLLERR;
    const POLLHUP: i16 = libc::POLLHUP;

    fn sockaddr(dst: [u8; 4], port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: port.to_be(),
            // s_addr is the address in network byte order: the u32 whose
            // little-endian memory layout IS dst (htonl equivalence).
            sin_addr: libc::in_addr {
                s_addr: u32::from_le_bytes(dst),
            },
            sin_zero: [0; 8],
        }
    }

    pub(super) fn trace_tcp(dst: [u8; 4], port: i64, max_ttl: i64, per_hop_ms: i64) -> TraceResult {
        let dst_str = format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]);
        let mut res = TraceResult {
            method: "tcp".into(),
            dst_ip: dst_str.clone(),
            ..Default::default()
        };
        let src_port = fixed_port(dst, port as u16);
        for ttl in 1..=max_ttl {
            let hop = tcp_probe_once(dst, port as u16, ttl as i32, per_hop_ms, src_port);
            match hop {
                None => res.hops.push(TraceHop {
                    ttl,
                    ..Default::default()
                }),
                Some(h) => {
                    let ip = h.ip.clone();
                    res.hops.push(h);
                    if ip == dst_str {
                        res.end_state = "reached".into();
                        res.reached_ttl = ttl;
                        return res;
                    }
                }
            }
        }
        res.end_state = "max_ttl".into();
        res
    }

    /// One TTL-limited connect: the responding hop (destination IP = the
    /// target itself, including the refused case) or None on silence.
    fn tcp_probe_once(
        dst: [u8; 4],
        port: u16,
        ttl: i32,
        per_hop_ms: i64,
        src_port: u16,
    ) -> Option<TraceHop> {
        unsafe {
            let fd = libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            );
            if fd < 0 {
                return None;
            }
            let _guard = FdGuard(fd);
            if prep_probe_socket(fd, ttl, src_port).is_err() {
                return None;
            }
            let addr = sockaddr(dst, port);
            let rc = libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            );
            if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS)
            {
                return None;
            }
            let started = std::time::Instant::now();
            let rev = ppoll_fd(fd, POLLOUT, per_hop_ms)?;
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            // SO_ERROR first regardless of which bit poll set: a refused
            // connection surfaces as ECONNREFUSED here on every kernel.
            let mut soerr: i32 = 0;
            let mut len = std::mem::size_of::<i32>() as u32;
            let rc = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut soerr as *mut _ as *mut _,
                &mut len,
            );
            if rc == 0 && (soerr == 0 || soerr == libc::ECONNREFUSED) {
                return Some(TraceHop {
                    ttl: ttl as i64,
                    ip: format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]),
                    ms,
                    ..Default::default()
                });
            }
            if rev & (POLLERR | POLLHUP) != 0 {
                let dst_str = format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]);
                if let Some(ip) = read_err_queue(fd, &dst_str) {
                    return Some(TraceHop {
                        ttl: ttl as i64,
                        ip,
                        ms,
                        ..Default::default()
                    });
                }
            }
            None
        }
    }

    pub(super) fn trace_icmp(
        dst: [u8; 4],
        _port: i64,
        max_ttl: i64,
        per_hop_ms: i64,
    ) -> TraceResult {
        let dst_str = format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]);
        let mut res = TraceResult {
            method: "icmp".into(),
            dst_ip: dst_str.clone(),
            ..Default::default()
        };
        unsafe {
            let fd = libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            );
            if fd < 0 {
                res.end_state = "error".into();
                res.err = format!("icmp socket: {}", std::io::Error::last_os_error());
                return res;
            }
            let _guard = FdGuard(fd);
            let one: i32 = 1;
            // IP_RECVTTL: without the cmsg the reply TTL stays unknown, but
            // the trace still works — ignore failure.
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                &one as *const _ as *const _,
                std::mem::size_of::<i32>() as u32,
            );
            let addr = sockaddr(dst, 0);
            for ttl in 1..=max_ttl {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_TTL,
                    &ttl as *const _ as *const _,
                    std::mem::size_of::<i32>() as u32,
                );
                let mut pkt = [0u8; 24];
                pkt[0] = 8; // echo request; kernel fills id + checksum
                pkt[6..8].copy_from_slice(&(ttl as u16).to_be_bytes()); // seq identifies the probe
                pkt[8..23].copy_from_slice(b"mibee-pathprobe"); // 15 bytes
                let started = std::time::Instant::now();
                let rc = libc::sendto(
                    fd,
                    pkt.as_ptr() as *const _,
                    pkt.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                );
                if rc < 0 {
                    continue;
                }
                match icmp_recv_once(fd, &dst_str, ttl as u16, per_hop_ms, started) {
                    None => res.hops.push(TraceHop {
                        ttl,
                        ..Default::default()
                    }),
                    Some(h) => {
                        let is_dst = h.ip == dst_str;
                        let reply_ttl = h.reply_ttl;
                        res.hops.push(h);
                        if is_dst {
                            res.end_state = "reached".into();
                            res.reached_ttl = ttl;
                            res.reply_ttl = reply_ttl;
                            return res;
                        }
                    }
                }
            }
        }
        res.end_state = "max_ttl".into();
        res
    }

    /// Wait for an echo reply (type 0, seq match, reply TTL via cmsg) or an
    /// error-queue Time Exceeded for this probe.
    fn icmp_recv_once(
        fd: i32,
        dst_str: &str,
        ttl: u16,
        per_hop_ms: i64,
        started: std::time::Instant,
    ) -> Option<TraceHop> {
        let deadline = started + std::time::Duration::from_millis(per_hop_ms.max(1) as u64);
        loop {
            let remain = deadline.saturating_duration_since(std::time::Instant::now());
            if remain.is_zero() {
                return None;
            }
            let rev = unsafe { ppoll_fd(fd, POLLIN, remain.as_millis() as i64) }?;
            unsafe {
                if rev & POLLERR != 0 {
                    if let Some(ip) = read_err_queue(fd, dst_str) {
                        let ms = started.elapsed().as_secs_f64() * 1000.0;
                        return Some(TraceHop {
                            ttl: ttl as i64,
                            ip,
                            ms,
                            ..Default::default()
                        });
                    }
                    continue;
                }
                let mut buf = [0u8; 2048];
                let mut oob = [0u8; 512];
                let mut iov = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut _,
                    iov_len: buf.len(),
                };
                let mut mh: libc::msghdr = std::mem::zeroed();
                mh.msg_iov = &mut iov;
                mh.msg_iovlen = 1;
                mh.msg_control = oob.as_mut_ptr() as *mut _;
                mh.msg_controllen = oob.len() as _;
                let n = libc::recvmsg(fd, &mut mh, libc::MSG_DONTWAIT);
                if n < 0 {
                    continue;
                }
                let n = n as usize;
                if n >= 16 && buf[0] == 0 && u16::from_be_bytes([buf[6], buf[7]]) == ttl {
                    let ms = started.elapsed().as_secs_f64() * 1000.0;
                    return Some(TraceHop {
                        ttl: ttl as i64,
                        ip: dst_str.to_string(),
                        ms,
                        reply_ttl: reply_ttl_from_cmsg(&oob[..mh.msg_controllen as usize]),
                    });
                }
            }
        }
    }

    /// Socket options common to both probes: IP_TTL, IP_RECVERR, and the
    /// fixed source port (TCP only; 0 skips the bind).
    unsafe fn prep_probe_socket(fd: i32, ttl: i32, src_port: u16) -> Result<(), ()> {
        let ttl = ttl;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        ) != 0
        {
            return Err(());
        }
        let one: i32 = 1;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            &one as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        ) != 0
        {
            return Err(());
        }
        if src_port > 0 {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const _,
                std::mem::size_of::<i32>() as u32,
            ) != 0
            {
                return Err(());
            }
            // Drain stale error-queue entries a previous attempt (same
            // 5-tuple) may have left behind before rebinding.
            drain_err_queue(fd);
            let a = sockaddr([0, 0, 0, 0], src_port);
            if libc::bind(
                fd,
                &a as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            ) != 0
            {
                return Err(());
            }
        }
        Ok(())
    }

    unsafe fn drain_err_queue(fd: i32) {
        let mut buf = [0u8; 512];
        let mut oob = [0u8; 512];
        for _ in 0..32 {
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut mh: libc::msghdr = std::mem::zeroed();
            mh.msg_iov = &mut iov;
            mh.msg_iovlen = 1;
            mh.msg_control = oob.as_mut_ptr() as *mut _;
            mh.msg_controllen = oob.len() as _;
            let n = libc::recvmsg(fd, &mut mh, libc::MSG_DONTWAIT | libc::MSG_ERRQUEUE);
            if n < 0 || mh.msg_controllen == 0 {
                return;
            }
        }
    }

    /// One error-queue entry: ICMP type 11 (Time Exceeded) yields the hop;
    /// type 3 from the destination itself means reached; anything else is
    /// ignored (None).
    unsafe fn read_err_queue(fd: i32, dst_str: &str) -> Option<String> {
        let mut buf = [0u8; 512];
        let mut oob = [0u8; 512];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut mh: libc::msghdr = std::mem::zeroed();
        mh.msg_iov = &mut iov;
        mh.msg_iovlen = 1;
        mh.msg_control = oob.as_mut_ptr() as *mut _;
        mh.msg_controllen = oob.len() as _;
        let n = libc::recvmsg(fd, &mut mh, libc::MSG_DONTWAIT | libc::MSG_ERRQUEUE);
        if n < 0 {
            return None;
        }
        let ctl = &oob[..mh.msg_controllen as usize];
        let mut cmsg = libc::CMSG_FIRSTHDR(&mh);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::IPPROTO_IP
                && hdr.cmsg_type == libc::IP_RECVERR
                && hdr.cmsg_len >= libc::CMSG_LEN(std::mem::size_of::<ErrEntry>() as u32) as _
            {
                let data = libc::CMSG_DATA(cmsg) as *const u8;
                let ee = std::slice::from_raw_parts(data, std::mem::size_of::<ErrEntry>());
                let origin = ee[4];
                let typ = ee[5];
                if origin != 2 {
                    // SO_EE_ORIGIN_ICMP
                    return None;
                }
                let ip = err_queue_offender(ee);
                if typ == 11 {
                    return Some(ip);
                }
                if typ == 3 {
                    // Unreachable: the destination itself answered. Loopback
                    // RSTs carry a zeroed offender sockaddr, so fall back to
                    // the connect target.
                    let ip = if ip.is_empty() {
                        dst_str.to_string()
                    } else {
                        ip
                    };
                    if ip == dst_str {
                        return Some(ip);
                    }
                }
                return None;
            }
            cmsg = libc::CMSG_NXTHDR(&mh, cmsg);
        }
        let _ = ctl;
        None
    }

    /// sock_extended_err layout the queue parser reads (errno/origin/type/
    /// code/info/data, then padding, then the offender sockaddr_in).
    type ErrEntry = [u8; 24];

    /// The offender sockaddr_in inside the extended-error payload: family
    /// (LE u16) at 16, address at 20..24 (Go errQueueOffender parity).
    pub(super) fn err_queue_offender(data: &[u8]) -> String {
        if data.len() < 24 || u16::from_le_bytes([data[16], data[17]]) != libc::AF_INET as u16 {
            return String::new();
        }
        format!("{}.{}.{}.{}", data[20], data[21], data[22], data[23])
    }

    /// Reply TTL from the IP_TTL cmsg of a regular recvmsg.
    unsafe fn reply_ttl_from_cmsg(oob: &[u8]) -> i64 {
        let mut mh: libc::msghdr = std::mem::zeroed();
        mh.msg_control = oob.as_ptr() as *mut libc::c_void;
        mh.msg_controllen = oob.len() as _;
        let mut cmsg = libc::CMSG_FIRSTHDR(&mh);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::IPPROTO_IP
                && hdr.cmsg_type == libc::IP_TTL
                && hdr.cmsg_len >= libc::CMSG_LEN(4) as _
            {
                let data = libc::CMSG_DATA(cmsg) as *const i32;
                return *data as i64;
            }
            cmsg = libc::CMSG_NXTHDR(&mh, cmsg);
        }
        0
    }

    /// ppoll(2) on one fd, EINTR-safe; None = timeout/error/zero revents.
    unsafe fn ppoll_fd(fd: i32, events: i16, timeout_ms: i64) -> Option<i16> {
        loop {
            let mut pfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let ts = libc::timespec {
                tv_sec: (timeout_ms / 1000) as _,
                tv_nsec: ((timeout_ms % 1000) * 1_000_000) as _,
            };
            let rc = libc::ppoll(&mut pfd, 1, &ts, std::ptr::null());
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return None;
            }
            if rc == 0 || pfd.revents == 0 {
                return None;
            }
            return Some(pfd.revents);
        }
    }

    struct FdGuard(pub i32);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
}

// Non-Linux: the walk refuses cleanly (the `trace` capability is only
// declared on Linux builds).
#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;
    pub(super) fn trace_tcp(
        _dst: [u8; 4],
        _port: i64,
        _max_ttl: i64,
        _per_hop_ms: i64,
    ) -> TraceResult {
        unsupported("tcp")
    }
    pub(super) fn trace_icmp(
        _dst: [u8; 4],
        _port: i64,
        _max_ttl: i64,
        _per_hop_ms: i64,
    ) -> TraceResult {
        unsupported("icmp")
    }
    pub(super) fn err_queue_offender(_data: &[u8]) -> String {
        String::new()
    }
    fn unsupported(method: &str) -> TraceResult {
        TraceResult {
            method: method.to_string(),
            end_state: "error".into(),
            err: "path tracing is only supported on Linux".into(),
            ..Default::default()
        }
    }
}

/// Offender-sockaddr extraction, exposed for tests on every platform.
pub fn err_queue_offender(data: &[u8]) -> String {
    imp::err_queue_offender(data)
}

/// Public test/diagnostic surface for the fixed-port derivation.
pub fn fixed_port_for(dst: [u8; 4], port: u16) -> u16 {
    fixed_port(dst, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_port_is_stable_and_in_range() {
        let a = fixed_port_for([93, 184, 216, 34], 443);
        assert_eq!(a, fixed_port_for([93, 184, 216, 34], 443));
        assert!((40000..60000).contains(&a));
        assert_ne!(a, fixed_port_for([93, 184, 216, 35], 443));
        assert_ne!(a, fixed_port_for([93, 184, 216, 34], 80));
    }

    #[test]
    fn host_port_derivation_by_module() {
        let (h, p) = host_port_for_trace("http", "https://www.example.org/");
        assert_eq!((h.as_str(), p), ("www.example.org", 443));
        let (h, p) = host_port_for_trace("http", "http://www.example.org:8080/x");
        assert_eq!((h.as_str(), p), ("www.example.org", 8080));
        let (h, p) = host_port_for_trace("http", "www.example.org");
        assert_eq!((h.as_str(), p), ("www.example.org", 80));
        let (h, p) = host_port_for_trace("tls", "example.com:8443");
        assert_eq!((h.as_str(), p), ("example.com", 8443));
        let (h, p) = host_port_for_trace("tcp", "203.0.113.10:53");
        assert_eq!((h.as_str(), p), ("203.0.113.10", 53));
        let (h, p) = host_port_for_trace("icmp", "1.1.1.1");
        assert_eq!((h.as_str(), p), ("1.1.1.1", 0));
        let (h, p) = host_port_for_trace("dns", "example.com");
        assert_eq!((h.as_str(), p), ("example.com", 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn offender_extraction() {
        let mut data = [0u8; 24];
        data[16..18].copy_from_slice(&(libc::AF_INET as u16).to_le_bytes());
        data[20..24].copy_from_slice(&[93, 184, 216, 1]);
        assert_eq!(err_queue_offender(&data), "93.184.216.1");
        data[16..18].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(err_queue_offender(&data), "");
        assert_eq!(err_queue_offender(&data[..20]), "");
    }

    #[test]
    fn reserved_gate() {
        assert!(!trace_host_allowed("127.0.0.1"));
        assert!(!trace_host_allowed("169.254.1.1"));
        assert!(!trace_host_allowed("224.0.0.1"));
        assert!(!trace_host_allowed("0.0.0.0"));
        assert!(!trace_host_allowed("192.0.2.9"));
        assert!(!trace_host_allowed("203.0.113.9"));
        // Private stays traceable; hostnames pass through.
        assert!(trace_host_allowed("192.168.2.1"));
        assert!(trace_host_allowed("www.example.org"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn loopback_tcp_reaches_in_one_hop() {
        // A listening loopback port: connect completes at TTL 1.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port() as i64;
        let tr = Tracer::new(4, 300);
        let res = tr.trace_host("127.0.0.1", port, "tcp").await;
        assert_eq!(res.end_state, "reached", "err={}", res.err);
        assert_eq!(res.reached_ttl, 1);
        assert_eq!(res.hops[0].ip, "127.0.0.1");
        // Refused (nothing listening further down the ephemeral range) is
        // still "reached": the destination itself answered with an RST.
        let res2 = tr.trace_host("127.0.0.1", 9, "tcp").await;
        assert_eq!(
            res2.end_state, "reached",
            "refused counts as reached, err={}",
            res2.err
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn icmp_gateway_or_silent_ttl1() {
        // Unprivileged ICMP ping sockets need ping_group_range; skip when the
        // kernel refuses (Go test parity).
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
            if fd < 0 {
                eprintln!("skipping: no unprivileged ICMP ping sockets here");
                return;
            }
            libc::close(fd);
        }
        let tr = Tracer::new(1, 400);
        let res = tr.trace_host("223.5.5.5", 0, "icmp").await;
        assert_ne!(res.end_state, "error", "err={}", res.err);
        assert_eq!(
            res.end_state, "max_ttl",
            "TTL1 to an off-link address cannot reach"
        );
        if let Some(h0) = res.hops.first() {
            assert_ne!(
                h0.ip, "223.5.5.5",
                "TTL1 hop is the destination - loopback route?"
            );
        }
    }

    #[tokio::test]
    async fn unresolvable_host_is_error_sample() {
        let tr = Tracer::new(4, 100);
        let res = tr.trace_host("no-such-host.invalid", 443, "auto").await;
        assert_eq!(res.end_state, "error");
        assert!(res.err.contains("resolve"));
    }

    #[tokio::test]
    async fn trace_spec_shapes_report() {
        let tr = Tracer::new(2, 200);
        // Empty target: stored error sample, not a failure.
        let spec = ProbeTargetSpec {
            id: 3,
            module: "http".into(),
            target: String::new(),
            ..Default::default()
        };
        let r = trace_spec(&tr, &spec, "baseline").await;
        assert_eq!(r.end_state, "error");
        assert_eq!(r.err, "cannot derive host from target");
        // Reserved literal: refused (#719 gate).
        let spec = ProbeTargetSpec {
            id: 4,
            module: "icmp".into(),
            target: "127.0.0.1".into(),
            ..Default::default()
        };
        let r = trace_spec(&tr, &spec, "baseline").await;
        assert_eq!(r.end_state, "error");
        assert_eq!(r.err, "reserved target refused");
    }
}
