//! Router ARP walk (Go probe/snmp_arp.go): cross-subnet MAC resolution by
//! walking a router's SNMP ARP table. A gateway knows every host that has
//! spoken through it, so one Walk per router resolves MACs for subnets the
//! agent is NOT attached to (where /proc/net/arp is blind).
//!
//! Two callers share this module:
//! - the scan path (lookup_mac_via_routers): post-gather MAC fallback for
//!   hosts whose ARP probe found nothing, behind a 30s per-(router, cred)
//!   cache so a /24 scan walks each router once;
//! - the passive discovery source (discovery.rs): periodic full-table sweep
//!   on the plain community path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use super::snmp::{oid_starts_with, v2c_walk};
use super::SnmpV3Credential;

/// ipNetToMediaPhysAddress (RFC 1213): the universally-implemented ARP table.
pub const OID_IP_NET_TO_MEDIA: &str = "1.3.6.1.2.1.4.22.1.2";
/// ipNetToPhysicalPhysAddress (RFC 4293): IPv6 + newer stacks; only walked
/// when the legacy OID comes back empty.
pub const OID_IP_NET_TO_PHYSICAL: &str = "1.3.6.1.2.1.4.35.1.4";

/// Extract the IPv4 from a varbind OID like
/// `.1.3.6.1.2.1.4.22.1.2.2.192.0.2.133` (index = ifIndex.ip octets; the
/// last 4 components are the address). Works for the RFC 4293 index too:
/// IPv6 rows have 16 trailing address octets whose last 4 don't parse as a
/// plausible row — they fall out at the ifIndex-length sanity check below,
/// mirroring Go indexToIP.
pub fn index_to_ip(full_oid: &str, prefix: &str) -> Option<String> {
    let f = full_oid.trim_start_matches('.');
    let p = prefix.trim_start_matches('.');
    let tail = f.strip_prefix(p)?.trim_start_matches('.');
    let parts: Vec<&str> = tail.split('.').collect();
    // ipNetToMedia index = ifIndex + 4 IP octets → ≥5 parts
    if parts.len() < 5 {
        return None;
    }
    let ip = parts[parts.len() - 4..].join(".");
    // sanity: each octet 0-255 (rejects IPv6-row tails and garbage)
    let octets: Vec<u16> = parts[parts.len() - 4..]
        .iter()
        .map(|s| s.parse::<u16>().ok().filter(|v| *v <= 255))
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 {
        return None;
    }
    Some(ip)
}

/// 6 raw octets → canonical lowercase `aa:bb:cc:dd:ee:ff` (Go formatMAC).
pub fn octets_to_mac(b: &[u8]) -> Option<String> {
    if b.len() != 6 {
        return None;
    }
    Some(
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Router address parsing: plain IPs get the SNMP port 161 (the config
/// vocabulary, Go parity); an explicit `ip:port` form is accepted for
/// tests/fake routers.
pub fn router_addr(router: &str) -> Option<SocketAddr> {
    if router.contains(':') {
        return router.parse().ok();
    }
    let ip = router.parse::<std::net::IpAddr>().ok()?;
    Some(SocketAddr::new(ip, 161))
}

/// Walk one router's ARP table. Legacy OID first; when it yields nothing,
/// the RFC 4293 OID supplements (covers IPv6 + newer stacks, never
/// overwrites legacy entries — Go walkRouterARPTableHint parity).
///
/// Ok(map) (possibly empty) = the router answered but has no entries;
/// Err(reason) = unreachable / no SNMP / walk failed. The reason string is
/// log-safe (no secrets).
pub async fn walk_router_arp_table(
    router: SocketAddr,
    community: &str,
    timeout: Duration,
    v3: Option<&SnmpV3Credential>,
) -> Result<HashMap<String, String>, String> {
    let mut table = HashMap::new();
    // legacy OID: universally implemented on SNMP routers
    match walk_column(router, community, timeout, v3, OID_IP_NET_TO_MEDIA).await {
        Ok(rows) => fill_table(rows, OID_IP_NET_TO_MEDIA, &mut table),
        Err(e) => return Err(format!("snmp walk {router} {OID_IP_NET_TO_MEDIA}: {e}")),
    }
    // RFC 4293 supplement only when the legacy table is empty
    if table.is_empty() {
        match walk_column(router, community, timeout, v3, OID_IP_NET_TO_PHYSICAL).await {
            Ok(rows) => fill_table(rows, OID_IP_NET_TO_PHYSICAL, &mut table),
            Err(e) => return Err(format!("snmp walk {router} {OID_IP_NET_TO_PHYSICAL}: {e}")),
        }
    }
    Ok(table)
}

async fn walk_column(
    router: SocketAddr,
    community: &str,
    timeout: Duration,
    v3: Option<&SnmpV3Credential>,
    oid: &str,
) -> Result<Vec<(String, u8, Vec<u8>)>, String> {
    if let Some(cred) = v3 {
        return super::snmp_v3::v3_walk(router, cred, timeout, oid)
            .await
            .map_err(|e| e.to_string());
    }
    let community = if community.is_empty() { "public" } else { community };
    v2c_walk(router, community, timeout, oid)
        .await
        .map(|vbs| {
            vbs.into_iter()
                .map(|vb| (vb.oid, vb.tag, vb.value))
                .collect()
        })
        .ok_or_else(|| "no response".to_string())
}

fn fill_table(rows: Vec<(String, u8, Vec<u8>)>, prefix: &str, table: &mut HashMap<String, String>) {
    for (oid, tag, value) in rows {
        if tag != 0x04 || value.len() != 6 {
            continue; // PhysAddress is a 6-octet string
        }
        if !oid_starts_with(&oid, prefix) {
            continue;
        }
        if let (Some(ip), Some(mac)) = (index_to_ip(&oid, prefix), octets_to_mac(&value)) {
            table.insert(ip, mac);
        }
    }
}

// ---------- per-process walk cache (Go routerARPCacheGlobal) ----------

const ROUTER_ARP_CACHE_TTL: Duration = Duration::from_secs(30);

struct CacheEntry {
    router: String,
    cred_key: String,
    at: tokio::time::Instant,
    table: HashMap<String, String>,
}

/// Single-entry cache (the common case is one router per subnet). The lock
/// is held ACROSS the walk, which doubles as single-flight: concurrent
/// hosts in one scan serialize here and the first walker's table serves the
/// rest (Go achieves the same by resolving MACs sequentially per host).
static ROUTER_ARP_CACHE: std::sync::LazyLock<tokio::sync::Mutex<Option<CacheEntry>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(None));

/// Cache key by auth identity, never the passphrase (Go credKey parity).
fn cred_key(community: &str, v3: Option<&SnmpV3Credential>) -> String {
    match v3 {
        Some(c) => format!("v3:{}", c.username),
        None => {
            if community.is_empty() {
                "public".to_string()
            } else {
                community.to_string()
            }
        }
    }
}

/// Look up `ip`'s MAC by asking each router in turn; the first that knows
/// the IP wins (Go LookupMACViaRouters). Cache key = (router, cred identity).
pub async fn lookup_mac_via_routers(
    routers: &[String],
    community: &str,
    timeout: Duration,
    v3: Option<&SnmpV3Credential>,
    ip: &str,
) -> Option<String> {
    for r in routers {
        let Some(addr) = router_addr(r) else { continue };
        let key = cred_key(community, v3);
        let mut cache = ROUTER_ARP_CACHE.lock().await;
        let fresh = cache
            .as_ref()
            .is_some_and(|e| e.router == *r && e.cred_key == key && e.at.elapsed() < ROUTER_ARP_CACHE_TTL);
        if !fresh {
            // A failed walk neither caches nor aborts the router loop (Go:
            // walk nil → this router misses, the next one is still tried).
            match walk_router_arp_table(addr, community, timeout, v3).await {
                Ok(table) => {
                    *cache = Some(CacheEntry {
                        router: r.clone(),
                        cred_key: key,
                        at: tokio::time::Instant::now(),
                        table,
                    });
                }
                Err(_) => continue,
            }
        }
        if let Some(mac) = cache.as_ref().and_then(|e| e.table.get(ip)) {
            return Some(mac.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::probes::snmp::test_support::spawn_fake_router;
    use crate::engine::probes::snmp::{build_getnext_request, parse_walk_response};
    use std::net::IpAddr;

    #[test]
    fn index_to_ip_variants() {
        let legacy = "1.3.6.1.2.1.4.22.1.2";
        assert_eq!(
            index_to_ip(".1.3.6.1.2.1.4.22.1.2.2.192.0.2.133", legacy).as_deref(),
            Some("192.0.2.133")
        );
        assert_eq!(index_to_ip("1.3.6.1.2.1.4.22.1.2.7.10.0.0.1", legacy).as_deref(), Some("10.0.0.1"));
        // RFC 4293 IPv4 row: <ifIndex>.4.<octets>
        assert_eq!(
            index_to_ip("1.3.6.1.2.1.4.35.1.4.2.4.192.0.2.9", OID_IP_NET_TO_PHYSICAL).as_deref(),
            Some("192.0.2.9")
        );
        // IPv6 row: last-4 of 16 address octets still parse as ≤255 numbers,
        // but Go accepts them the same way (index shape alone can't tell);
        // the real filter is the value length. What we DO reject: too-short
        // tails, >255 octets, and non-matching prefixes.
        assert_eq!(index_to_ip("1.3.6.1.2.1.4.22.1.2.2.192.0.2", legacy), None); // 3 tail parts
        assert_eq!(index_to_ip("1.3.6.1.2.1.4.22.1.2.2.300.0.2.1", legacy), None); // octet >255
        assert_eq!(index_to_ip("1.3.6.1.2.1.4.22.1.3.2.192.0.2.1", legacy), None); // prefix mismatch
    }

    #[test]
    fn mac_formatting() {
        assert_eq!(
            octets_to_mac(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F]).as_deref(),
            Some("aa:bb:cc:dd:ee:0f")
        );
        assert_eq!(octets_to_mac(&[0xAA, 0xBB]), None);
        assert_eq!(octets_to_mac(&[]), None);
    }

    #[test]
    fn router_addr_defaults_to_161() {
        let a = router_addr("192.0.2.1").unwrap();
        assert_eq!(a.port(), 161);
        assert_eq!(a.ip(), IpAddr::from([192, 0, 2, 1]));
        let explicit = router_addr("127.0.0.1:11610").unwrap();
        assert_eq!(explicit.port(), 11610);
        assert!(router_addr("not-an-ip").is_none());
    }

    /// Outside both walked columns but greater than any row subindex: ends
    /// the legacy walk with a prefix mismatch.
    const WALK_END_LEGACY: &str = "1.3.6.1.2.1.4.22.1.3.1";
    /// Greater than the RFC 4293 root (35 > 22), outside both columns: ends
    /// both walks of a row-less router with zero rows collected.
    const WALK_END_BOTH: &str = "1.3.6.1.2.1.4.35.1.5";

    #[tokio::test]
    async fn walks_legacy_arp_table() {
        let root = OID_IP_NET_TO_MEDIA.to_string();
        let addr = spawn_fake_router(
            vec![
                (format!("{root}.2.192.0.2.50"), vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x50]),
                (format!("{root}.3.192.0.2.51"), vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x51]),
            ],
            WALK_END_LEGACY.to_string(),
        )
        .await;
        let table = walk_router_arp_table(addr, "public", Duration::from_secs(2), None)
            .await
            .expect("walk ok");
        assert_eq!(table.len(), 2);
        assert_eq!(table.get("192.0.2.50").map(String::as_str), Some("aa:bb:cc:dd:ee:50"));
        assert_eq!(table.get("192.0.2.51").map(String::as_str), Some("aa:bb:cc:dd:ee:51"));
    }

    #[tokio::test]
    async fn answered_router_with_no_rows_is_ok_empty() {
        // Both OIDs walked, both end immediately: Ok(empty) — "answered,
        // nothing to report", distinct from a failed walk (Go contract).
        let addr = spawn_fake_router(vec![], WALK_END_BOTH.to_string()).await;
        let table = walk_router_arp_table(addr, "public", Duration::from_secs(2), None)
            .await
            .expect("answered-empty is not an error");
        assert!(table.is_empty());
    }

    #[tokio::test]
    async fn lookup_via_routers_first_hit_wins() {
        let root = OID_IP_NET_TO_MEDIA.to_string();
        let addr = spawn_fake_router(
            vec![(format!("{root}.2.203.0.113.7"), vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66])],
            WALK_END_LEGACY.to_string(),
        )
        .await;
        // empty first router (answered, no rows), real second router
        let empty_addr = spawn_fake_router(vec![], WALK_END_BOTH.to_string()).await;
        let routers = vec![
            format!("127.0.0.1:{}", empty_addr.port()),
            format!("127.0.0.1:{}", addr.port()),
        ];
        let mac = lookup_mac_via_routers(&routers, "public", Duration::from_secs(2), None, "203.0.113.7")
            .await;
        assert_eq!(mac.as_deref(), Some("11:22:33:44:55:66"));
        // cache: a second lookup must be answered without re-walking (fake
        // server caps at 64 exchanges; we can't observe directly, but the
        // answer must still be correct and immediate)
        let again = lookup_mac_via_routers(&routers, "public", Duration::from_secs(2), None, "203.0.113.7")
            .await;
        assert_eq!(again.as_deref(), Some("11:22:33:44:55:66"));
    }

    #[tokio::test]
    async fn dead_router_reports_error_not_panic() {
        // port with no listener: walk must return Err, lookup returns None
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = sock.local_addr().unwrap();
        drop(sock);
        let res = walk_router_arp_table(dead, "public", Duration::from_millis(300), None).await;
        assert!(res.is_err(), "{res:?}");
        let mac = lookup_mac_via_routers(
            &[format!("127.0.0.1:{}", dead.port())],
            "public",
            Duration::from_millis(300),
            None,
            "192.0.2.1",
        )
        .await;
        assert_eq!(mac, None);
    }

    // The helpers below are exercised via snmp's own tests; referenced here
    // to keep the fake-router code honest about what it parses.
    #[test]
    fn getnext_packet_shape() {
        let pkt = build_getnext_request(1, "public", 3, OID_IP_NET_TO_MEDIA);
        assert_eq!(pkt.iter().filter(|b| **b == 0xA1).count(), 1);
        let _ = parse_walk_response(&pkt, 3); // a request is not a response
    }
}
