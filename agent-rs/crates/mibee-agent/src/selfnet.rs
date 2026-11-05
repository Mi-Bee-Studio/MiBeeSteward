//! Self-network detection (#686): enumerate the agent host's own IPv4
//! on-link subnets from `/proc/net/route` (Linux-only product target), so
//! the center can see where the agent ACTUALLY sits — as opposed to
//! `network_cidr`, the configured claim.
//!
//! Pure parsing, no netlink/iface crates (the workspace stays
//! dependency-light): route rows carry little-endian hex for
//! Destination/Gateway/Mask; the on-link rows (gateway bit clear,
//! destination non-zero) give each interface's subnet; the default-route
//! row names the primary interface.

use crate::wire::SelfInterface;

/// hex little-endian ("0000A8C0") → dotted IPv4. None on malformed input.
fn hex_le_ipv4(s: &str) -> Option<String> {
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let oct = |i: usize| u8::from_str_radix(&s[8 - 2 * i - 2..8 - 2 * i], 16).ok();
    Some(format!(
        "{}.{}.{}.{}",
        oct(0)?,
        oct(1)?,
        oct(2)?,
        oct(3)?
    ))
}

/// Contiguous dotted mask → prefix length; None for non-contiguous/invalid.
fn mask_to_prefix(mask: &str) -> Option<u8> {
    let mut prefix = 0u8;
    let mut seen_zero = false;
    for oct in mask.split('.') {
        let v: u8 = oct.parse().ok()?;
        match v {
            255 => {
                if seen_zero {
                    return None;
                }
                prefix += 8;
            }
            0 => seen_zero = true,
            _ => {
                // 254/252/…/128: the one octet allowed to open the zero run.
                // Contiguous iff ones + trailing zeros == 8 (240 = 4+4 ✓,
                // 196 = 3+2 ✗).
                if seen_zero {
                    return None;
                }
                if v.count_ones() as u8 + v.trailing_zeros() as u8 != 8 {
                    return None;
                }
                prefix += v.count_ones() as u8;
                seen_zero = true;
            }
        }
    }
    Some(prefix)
}

/// Parse a `/proc/net/route` dump into self interfaces. Exposed for tests;
/// `detect_self_networks` reads the live file.
pub fn parse_route_table(content: &str) -> Vec<SelfInterface> {
    let mut default_iface: Option<String> = None;
    let mut out: Vec<SelfInterface> = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = Default::default();

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let iface = cols[0];
        if iface == "lo" {
            continue;
        }
        let Some(dst) = hex_le_ipv4(cols[1]) else { continue };
        let Some(mask) = hex_le_ipv4(cols[7]) else { continue };
        let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
        let gateway_route = flags & 0x2 != 0; // RTF_GATEWAY

        if dst == "0.0.0.0" {
            if gateway_route && default_iface.is_none() {
                default_iface = Some(iface.to_string());
            }
            continue;
        }
        if gateway_route {
            continue; // a routed (off-link) subnet, not the iface's own
        }
        let Some(prefix) = mask_to_prefix(&mask) else { continue };
        if prefix == 0 {
            continue;
        }
        let cidr = format!("{dst}/{prefix}");
        // Link-local autoconf space never yields LAN devices.
        if cidr.starts_with("169.254.") {
            continue;
        }
        if !seen.insert((iface.to_string(), cidr.clone())) {
            continue;
        }
        out.push(SelfInterface {
            name: iface.to_string(),
            cidr,
            primary: false, // stamped below once the default iface is known
        });
    }

    if let Some(def) = default_iface.as_deref() {
        for si in &mut out {
            if si.name == def {
                si.primary = true;
            }
        }
        // Primary first: it drives the center's fill-the-blank network hint.
        out.sort_by_key(|si| !si.primary);
    }
    out
}

/// Detect this host's IPv4 on-link subnets. Empty on any failure (non-Linux,
/// unreadable table): detection is best-effort, reporting must never fail.
pub fn detect_self_networks() -> Vec<SelfInterface> {
    match std::fs::read_to_string("/proc/net/route") {
        Ok(content) => parse_route_table(&content),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0  00000000 0100A8C0 0003 0 0 0 00000000 0 0 0
eth0  0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0
wlan0 00003FA8 00000000 0001 0 0 0 00FFFFFF 0 0 0
lo    0000007F 00000000 0001 0 0 0 00FFFFFF 0 0 0
eth1  0010A8C0 00000000 0001 0 0 0 F0FFFFFF 0 0 0
";

    #[test]
    fn parses_on_link_subnets_with_primary() {
        let got = parse_route_table(TABLE);
        assert_eq!(got.len(), 3, "lo skipped: {got:?}");
        assert_eq!(got[0].name, "eth0");
        assert_eq!(got[0].cidr, "192.168.0.0/24");
        assert!(got[0].primary, "default-route iface is primary");
        // 00003FA8 little-endian → 168.63.0.0 (0x3F = 63 decimal)
        assert_eq!(got[1].name, "wlan0");
        assert_eq!(got[1].cidr, "168.63.0.0/24");
        assert!(!got[1].primary);
        // 0010A8C0 → 192.168.16.0, mask F0FFFFFF (little-endian
        // 255.255.255.240) → /28
        assert_eq!(got[2].name, "eth1");
        assert_eq!(got[2].cidr, "192.168.16.0/28");
        assert!(!got[2].primary);
    }

    #[test]
    fn skips_link_local() {
        const T: &str = "\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0  0000FEA9 00000000 0001 0 0 0 00FFFF00 0 0 0
";
        // 0000FEA9 LE = 169.254.0.0 — link-local, must be skipped entirely.
        let got = parse_route_table(T);
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn no_default_route_means_no_primary() {
        const T: &str = "\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0  0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0
";
        let got = parse_route_table(T);
        assert_eq!(got.len(), 1);
        assert!(!got[0].primary);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        const T: &str = "\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0  0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0
garbage line
eth9  ZZ 00000000 0001 0 0 0 00FFFFFF 0 0 0
";
        let got = parse_route_table(T);
        assert_eq!(got.len(), 1, "{got:?}");
    }

    #[test]
    fn hex_and_mask_helpers() {
        assert_eq!(hex_le_ipv4("0000A8C0").as_deref(), Some("192.168.0.0"));
        assert_eq!(hex_le_ipv4("0100A8C0").as_deref(), Some("192.168.0.1"));
        assert_eq!(hex_le_ipv4("XYZ"), None);
        assert_eq!(mask_to_prefix("255.255.255.0"), Some(24));
        assert_eq!(mask_to_prefix("255.255.255.240"), Some(28));
        assert_eq!(mask_to_prefix("255.0.255.0"), None); // non-contiguous
        assert_eq!(mask_to_prefix("255.255.0.0"), Some(16));
    }
}
