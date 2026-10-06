//! TCP port spec: comma list with `lo-hi` ranges (max span 10000), deduped
//! sorted, then priority-reordered so fingerprint-relevant ports dial first
//! (Go probe/ports.go ordering).

pub const DEFAULT_PORT_SPEC: &str = "22,21,23,25,53,80,110,143,389,443,445,554,631,636,8554,1433,3306,3389,5432,5900,6379,8000,8080,8081,8443,8888,9000,9090,9100,9104,9113,9121,9187,9200,9443,11211,27017,161";

/// Fingerprint ports dial first (Go ports.go fingerprintPorts).
const FINGERPRINT_PORTS: [u16; 17] =
    [22, 80, 443, 8080, 8443, 8000, 554, 8554, 9090, 9100, 9104, 9113, 9121, 9187, 161, 3306, 5432];

pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let lo: u16 = a.trim().parse().map_err(|_| format!("bad port {part:?}"))?;
            let hi: u16 = b.trim().parse().map_err(|_| format!("bad port {part:?}"))?;
            if hi < lo {
                return Err(format!("inverted range {part:?}"));
            }
            if hi as u32 - lo as u32 > 10_000 {
                return Err(format!("range too wide {part:?}"));
            }
            for p in lo..=hi {
                out.push(p);
            }
        } else {
            let p: u16 = part.parse().map_err(|_| format!("bad port {part:?}"))?;
            out.push(p);
        }
    }
    for p in &out {
        if *p == 0 {
            return Err("port 0 invalid".to_string());
        }
    }
    out.sort();
    out.dedup();
    // fingerprint-relevant ports first, remaining ascending
    let mut prioritized: Vec<u16> = FINGERPRINT_PORTS.iter().copied().filter(|p| out.contains(p)).collect();
    prioritized.extend(out.iter().copied().filter(|p| !FINGERPRINT_PORTS.contains(p)));
    Ok(prioritized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spec_parses_fingerprint_first() {
        let ports = parse_port_spec(DEFAULT_PORT_SPEC).unwrap();
        assert_eq!(ports.len(), 38);
        assert_eq!(ports.first(), Some(&22));
        assert_eq!(ports[1], 80);
        assert_eq!(ports[2], 443);
        // 161 rides early with the fingerprint group despite being the max
        assert!(ports.iter().take(17).any(|p| *p == 161));
        assert_eq!(ports.last(), Some(&27017));
    }

    #[test]
    fn ranges_and_dedup() {
        let ports = parse_port_spec("9000-9003,9001,80").unwrap();
        assert_eq!(ports, vec![80, 9000, 9001, 9002, 9003]);
    }

    #[test]
    fn junk_rejected() {
        assert!(parse_port_spec("abc").is_err());
        assert!(parse_port_spec("10-5").is_err());
        assert!(parse_port_spec("1-20000").is_err());
        assert!(parse_port_spec("0").is_err());
    }
}
