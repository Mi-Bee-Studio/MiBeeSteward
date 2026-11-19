//! HostNet sampler (#746): the agent's own local-network facts, riding the
//! report meta so quality attribution can answer "did THIS vantage's own
//! network degrade, or the target".
//!
//! The parsers are pure functions over /proc file contents so tests drive
//! them without touching a filesystem; the linux collector reads the real
//! files and times one DNS resolution against the configured resolver hint.

use crate::wire::HostnetReport;
use std::collections::BTreeMap;

/// Parse /proc/net/dev into per-interface error/drop counters. Only the four
/// attribution-relevant counters are kept (rx/tx errors + drops); byte/packet
/// counts are inventory noise here. Lines without the expected column shape
/// (header rows, malformed) are skipped — a partial sample beats a failed
/// sample.
pub(crate) fn parse_proc_net_dev(content: &str) -> BTreeMap<String, BTreeMap<String, u64>> {
    let mut out = BTreeMap::new();
    for line in content.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|f| f.parse::<u64>().ok())
            .collect();
        if fields.len() < 12 {
            continue;
        }
        let mut counters = BTreeMap::new();
        counters.insert("rx_errors".to_string(), fields[2]);
        counters.insert("rx_dropped".to_string(), fields[3]);
        counters.insert("tx_errors".to_string(), fields[10]);
        counters.insert("tx_dropped".to_string(), fields[11]);
        out.insert(name.trim().to_string(), counters);
    }
    out
}

/// Parse /proc/net/route into the default-route fingerprint "iface|gateway"
/// (gateway dotted-quad; /proc stores it little-endian hex). '' when no
/// default route exists — the change detector treats '' as its own value, so
/// losing the default route IS a route event.
pub(crate) fn parse_proc_route(content: &str) -> String {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags ... (11 columns on real kernels;
        // be lenient — tests and future kernels may carry fewer).
        if fields.len() < 3 || fields[1] != "00000000" {
            continue;
        }
        let iface = fields[0].to_string();
        if fields[2] == "00000000" {
            // On-link default (no gateway): the interface alone pins it.
            return format!("{iface}|");
        }
        return format!("{iface}|{}", hex_le_to_ipv4(fields[2]));
    }
    String::new()
}

/// Little-endian hex (as /proc/net/route stores addresses) → dotted quad.
fn hex_le_to_ipv4(hex: &str) -> String {
    if hex.len() != 8 {
        return String::new();
    }
    let bytes: Vec<u8> = (0..4)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect();
    if bytes.len() != 4 {
        return String::new();
    }
    // /proc/net/route stores the address in network byte order read as
    // little-endian u32 hex: bytes are already big-endian order.
    format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
}

/// SNTP (RFC 4330) clock offset from one server reply (#749).
/// θ = ((t1 − t0) + (t2 − t3)) / 2, where t0/t3 are the client's send/receive
/// times and t1/t2 the server's receive/transmit timestamps from the packet
/// (bytes 32..48, NTP 1900-epoch seconds+fraction). `packet` must be a full
/// 48-byte reply with mode=server (4).
pub(crate) fn sntp_offset_ms(t0_ms: f64, packet: &[u8], t3_ms: f64) -> Result<f64, String> {
    if packet.len() < 48 {
        return Err("short sntp reply".to_string());
    }
    if packet[0] & 0x07 != 4 {
        return Err("not a server reply".to_string());
    }
    let t1 = ntp_ts_ms(&packet[32..40]);
    let t2 = ntp_ts_ms(&packet[40..48]);
    let t1 = t1.ok_or("bad receive timestamp")?;
    let t2 = t2.ok_or("bad transmit timestamp")?;
    // NTP era conversion: the server timestamp is wall-clock, the client
    // times are unix milliseconds — both share the epoch offset handled by
    // ntp_ts_ms, so the deltas are directly comparable.
    Ok(((t1 - t0_ms) + (t2 - t3_ms)) / 2.0)
}

/// NTP 64-bit timestamp (seconds + fraction since 1900-01-01) → unix
/// milliseconds. Returns None for the zero timestamp (server clock unset).
fn ntp_ts_ms(bytes: &[u8]) -> Option<f64> {
    if bytes.len() != 8 {
        return None;
    }
    let secs = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64;
    let frac = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as f64;
    if secs == 0.0 && frac == 0.0 {
        return None;
    }
    Some((secs - 2_208_988_800.0) * 1000.0 + frac / 4_294_967_296.0 * 1000.0)
}

/// Build the client's 48-byte SNTP request (vn=4, mode=client) — split out so
/// tests can pin the wire bytes the pool servers expect.
pub(crate) fn sntp_request() -> [u8; 48] {
    let mut pkt = [0u8; 48];
    pkt[0] = 0b00_100_011; // LI=0, VN=4, Mode=3 (client)
    pkt
}

fn unix_ms_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0)
}

/// One HostNet sample: raw counters + default-route fingerprint from the
/// /proc files, one timed DNS resolution against `dns_hint` (the center's
/// host — the resolution the report path itself depends on). Linux only;
/// other builds sample nothing (the meta field stays absent).
#[cfg(target_os = "linux")]
pub(crate) async fn sample_once(dns_hint: &str) -> (Option<HostnetReport>, f64) {
    let dev = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let iface_stats = parse_proc_net_dev(&dev);
    if iface_stats.is_empty() && route.is_empty() {
        return (None, 0.0); // nothing read: no sample, not an empty one
    }
    let mut note = String::new();
    let dns_start = std::time::Instant::now();
    let resolved = crate::engine::probes::tls::resolve_host(dns_hint).await;
    let dns_ms = resolved
        .map(|_| dns_start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    if resolved.is_none() {
        note = "dns resolve failed".to_string();
    }
    let report = HostnetReport {
        checked_at: crate::wire::now_rfc3339(),
        iface_stats,
        default_route: parse_proc_route(&route),
        dns_ms: (dns_ms * 10.0).round() / 10.0,
        note,
    };
    let offset = sntp_query().await;
    (Some(report), offset)
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn sample_once(_dns_hint: &str) -> (Option<HostnetReport>, f64) {
    (None, 0.0)
}

/// Sampling loop (#746/#749): one sample at startup, then every `every`.
/// Nothing here can wedge the report path — a failed sample just keeps the
/// previous cache and the next round retries. Public because the bin crate
/// (`main.rs`) drives it outside the lib.
pub async fn run_sampler(
    reporter: std::sync::Arc<crate::center::Reporter>,
    dns_hint: String,
    every: std::time::Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let (sample, offset) = sample_once(&dns_hint).await;
        reporter.set_hostnet_sample(sample, offset);
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = stop.changed() => return,
        }
    }
}

/// One SNTP round trip against the public pool. Failure = 0 (unknown), the
/// offset is auxiliary metadata and must never wedge the report loop.
#[cfg(target_os = "linux")]
async fn sntp_query() -> f64 {
    use std::time::Duration;
    let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return 0.0;
    };
    if sock.connect(("pool.ntp.org", 123)).await.is_err() {
        return 0.0;
    }
    let req = sntp_request();
    let t0 = unix_ms_f64();
    if sock.send(&req).await.is_err() {
        return 0.0;
    }
    let mut buf = [0u8; 48];
    if tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .is_err()
    {
        return 0.0;
    }
    let t3 = unix_ms_f64();
    sntp_offset_ms(t0, &buf, t3).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456789    987654    0    0    0     0          0         0  123456789    987654    0    0    0     0       0          0
  eth0: 99000000  120000000   17  4200    0     0          0         3  88000000  110000000    2   55    0     0       0          0
 corrupt-line-without-colon
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0 extra-fields-ignored
";

    #[test]
    fn proc_net_dev_extracts_error_counters() {
        let m = parse_proc_net_dev(PROC_NET_DEV);
        assert_eq!(m.len(), 3, "lo + eth0 + wlan0; corrupt line skipped");
        let eth = &m["eth0"];
        assert_eq!(eth["rx_errors"], 17);
        assert_eq!(eth["rx_dropped"], 4200);
        assert_eq!(eth["tx_errors"], 2);
        assert_eq!(eth["tx_dropped"], 55);
        assert_eq!(m["lo"]["rx_errors"], 0);
        assert_eq!(m["wlan0"]["tx_dropped"], 0);
        // Attribution-relevant counters only: no byte noise on the wire.
        assert!(!eth.contains_key("rx_bytes"));
    }

    #[test]
    fn proc_route_finds_default_gateway() {
        // Classic home-LAN default route: eth0 via 192.168.1.1.
        // 192.168.1.1 = C0A80101 big-endian; /proc stores 0101A8C0.
        let content = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\tC0A80100\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        assert_eq!(parse_proc_route(content), "eth0|192.168.1.1");
    }

    #[test]
    fn proc_route_onlink_default_and_none() {
        let onlink = "\
Iface\tDestination\tGateway\tFlags
wg0\t00000000\t00000000\t0003
";
        assert_eq!(parse_proc_route(onlink), "wg0|", "on-link default = iface only");
        assert_eq!(parse_proc_route("Iface\tDestination\tGateway\tFlags\n"), "");
    }

    #[test]
    fn sntp_request_shape() {
        let pkt = sntp_request();
        assert_eq!(pkt.len(), 48);
        assert_eq!(pkt[0] & 0x07, 3, "mode = client");
        assert_eq!((pkt[0] >> 3) & 0x07, 4, "version 4");
    }

    #[test]
    fn sntp_offset_symmetric_path_is_zero() {
        // Server rx/tx both exactly at the client's mid-point of a 10ms
        // round trip: offset 0.
        let mut full = [0u8; 48];
        full[0] = 0b00_100_100; // mode = server
        let put = |buf: &mut [u8], ms: f64| {
            let s = ms / 1000.0 + 2_208_988_800.0;
            let secs = s as u32;
            let frac = ((s - secs as f64) * 4_294_967_296.0) as u32;
            buf[..4].copy_from_slice(&secs.to_be_bytes());
            buf[4..].copy_from_slice(&frac.to_be_bytes());
        };
        let mid = 1_700_000_000_000.0; // unix ms
        put(&mut full[32..40], mid - 5.0); // t1
        put(&mut full[40..48], mid + 5.0); // t2
        let offset = sntp_offset_ms(mid - 5.0, &full, mid + 5.0).unwrap();
        assert!(offset.abs() < 0.01, "symmetric path = 0, got {offset}");
    }

    #[test]
    fn sntp_offset_detects_clock_ahead() {
        let mut full = [0u8; 48];
        full[0] = 0b00_100_100;
        let put = |buf: &mut [u8], ms: f64| {
            let s = ms / 1000.0 + 2_208_988_800.0;
            let secs = s as u32;
            let frac = ((s - secs as f64) * 4_294_967_296.0) as u32;
            buf[..4].copy_from_slice(&secs.to_be_bytes());
            buf[4..].copy_from_slice(&frac.to_be_bytes());
        };
        let t0 = 1_700_000_000_000.0;
        let t3 = t0 + 10.0;
        // Server clock 250ms AHEAD of local: t1/t2 sit +250 on the same path.
        put(&mut full[32..40], t0 + 5.0 + 250.0);
        put(&mut full[40..48], t0 + 5.0 + 250.0);
        let offset = sntp_offset_ms(t0, &full, t3).unwrap();
        assert!((offset - 250.0).abs() < 0.5, "got {offset}");
    }

    #[test]
    fn sntp_rejects_bad_replies() {
        assert!(sntp_offset_ms(0.0, &[0u8; 47], 0.0).is_err(), "short");
        let mut pkt = [0u8; 48];
        pkt[0] = 0b00_100_011; // client mode echoed back = not a server reply
        assert!(sntp_offset_ms(0.0, &pkt, 0.0).is_err());
        let mut pkt = [0u8; 48];
        pkt[0] = 0b00_100_100;
        assert!(sntp_offset_ms(0.0, &pkt, 0.0).is_err(), "zero timestamps");
    }
}
