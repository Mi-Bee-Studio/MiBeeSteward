//! Scan-target expansion: single IP, `a.b.c.d-e`, `a.b.c.d-a.b.c.d`, CIDR
//! (network+broadcast skipped, nmap semantics), comma lists. Reserved-range
//! guard unless allow_reserved (Go internal/cidrutil + engine/targets.go).

use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub enum ExpandError {
    Invalid(String),
    ReservedRange(String),
    TooManyHosts(String),
}

/// Go cidrutil.reservedClass: unspecified, loopback, link-local unicast,
/// multicast, limited broadcast, 240.0.0.0/4. (RFC 5737 documentation
/// ranges are deliberately NOT reserved — docs/configs use them freely.)
pub fn is_reserved(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast() || ip.octets()[0] >= 240
}

/// Expand a target spec into individual host IPs. Reserved targets are
/// rejected unless `allow_reserved` (the e2e/loadgen escape hatch).
pub fn expand_targets(spec: &str, allow_reserved: bool) -> Result<Vec<Ipv4Addr>, ExpandError> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        expand_part(part, allow_reserved, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn expand_part(part: &str, allow_reserved: bool, out: &mut Vec<Ipv4Addr>) -> Result<(), ExpandError> {
    if let Ok(net) = part.parse::<Ipv4Net>() {
        let net = net.trunc();
        if net.prefix_len() < 24 {
            // Go caps oversized ranges (max span 10000); a /23 is 510 hosts
            // which is fine, but reject anything larger than /16 hard.
            if net.prefix_len() < 16 {
                return Err(ExpandError::TooManyHosts(part.to_string()));
            }
        }
        for ip in net.hosts() {
            push_if_allowed(ip, part, allow_reserved, out)?;
        }
        // /31 and /32 have no "hosts" via hosts() — add all addresses
        if net.prefix_len() >= 31 {
            let mut n = u32::from(net.network());
            let end = u32::from(net.broadcast());
            while n <= end {
                push_if_allowed(Ipv4Addr::from(n), part, allow_reserved, out)?;
                n += 1;
            }
        }
        return Ok(());
    }
    if let Some((a, b)) = part.split_once('-') {
        let start: Ipv4Addr = a
            .trim()
            .parse()
            .map_err(|_| ExpandError::Invalid(part.to_string()))?;
        // "a.b.c.d-e" with a bare last octet, or a full IP on both sides.
        let end: Ipv4Addr = match b.trim().parse() {
            Ok(ip) => ip,
            Err(_) => {
                let n: u32 = b
                    .trim()
                    .parse()
                    .map_err(|_| ExpandError::Invalid(part.to_string()))?;
                if n > 255 {
                    return Err(ExpandError::Invalid(part.to_string()));
                }
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], n as u8)
            }
        };
        if u32::from(end) < u32::from(start) {
            return Err(ExpandError::Invalid(part.to_string()));
        }
        if u32::from(end) - u32::from(start) > 10_000 {
            return Err(ExpandError::TooManyHosts(part.to_string()));
        }
        for n in u32::from(start)..=u32::from(end) {
            push_if_allowed(Ipv4Addr::from(n), part, allow_reserved, out)?;
        }
        return Ok(());
    }
    let ip: Ipv4Addr = part.parse().map_err(|_| ExpandError::Invalid(part.to_string()))?;
    push_if_allowed(ip, part, allow_reserved, out)
}

fn push_if_allowed(
    ip: Ipv4Addr,
    part: &str,
    allow_reserved: bool,
    out: &mut Vec<Ipv4Addr>,
) -> Result<(), ExpandError> {
    if is_reserved(ip) && !allow_reserved {
        return Err(ExpandError::ReservedRange(format!("{ip} (in {part})")));
    }
    out.push(ip);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_list() {
        let ips = expand_targets("192.0.2.10, 192.0.2.11", false).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "192.0.2.10");
    }

    #[test]
    fn cidr_skips_network_and_broadcast() {
        let ips = expand_targets("198.51.100.0/30", true).unwrap();
        // /30 hosts(): .1 .2 (network .0 and broadcast .3 skipped)
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"198.51.100.1".parse::<Ipv4Addr>().unwrap()));
    }

    #[test]
    fn range_forms() {
        let a = expand_targets("198.51.100.10-198.51.100.12", true).unwrap();
        assert_eq!(a.len(), 3);
        let b = expand_targets("198.51.100.10-12", true).unwrap();
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn reserved_guard() {
        assert!(matches!(
            expand_targets("127.0.0.1", false),
            Err(ExpandError::ReservedRange(_))
        ));
        assert!(expand_targets("127.0.0.1", true).is_ok());
        assert!(expand_targets("192.0.2.1", false).is_ok(), "TEST-NET is scannable (docs use it)");
        assert!(matches!(
            expand_targets("224.0.0.5", false),
            Err(ExpandError::ReservedRange(_))
        ));
    }

    #[test]
    fn junk_rejected() {
        assert!(matches!(expand_targets("not-an-ip", true), Err(ExpandError::Invalid(_))));
        assert!(matches!(
            expand_targets("198.51.100.5-198.51.100.1", true),
            Err(ExpandError::Invalid(_))
        ));
        assert!(matches!(
            expand_targets("198.51.100.1-300", true),
            Err(ExpandError::Invalid(_))
        ));
    }
}
