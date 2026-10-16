//! ARP probe: read /proc/net/arp (3 attempts 200ms apart, 1s parsed cache
//! process-wide), MAC lowercased, OUI vendor lookup (Go probe/arp.go).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use super::{ev, probe_impl, Evidence, Probe, ProbeHint};

pub struct ArpProbe;

static CACHE: OnceLock<Mutex<Option<(SystemTime, Vec<ArpRow>)>>> = OnceLock::new();

#[derive(Clone)]
pub(crate) struct ArpRow {
    pub(crate) ip: String,
    pub(crate) mac: String,
    pub(crate) device: String,
}

probe_impl!(
    ArpProbe,
    "active:arp",
    |ip: IpAddr, hint: &ProbeHint| async move {
        for _ in 0..3 {
            if let Some(rows) = cached_arp().await {
                if let Some(row) = rows.iter().find(|r| r.ip == ip.to_string()) {
                    let mut e = ev("active:arp", "mac", ip, 1.0);
                    let mut rd = BTreeMap::new();
                    rd.insert("mac".into(), row.mac.clone());
                    rd.insert("device".into(), row.device.clone());
                    if let Some((vendor, prefix)) = hint.oui.lookup_full(&row.mac) {
                        rd.insert("vendor".into(), vendor);
                        rd.insert("oui_prefix".into(), prefix);
                    }
                    e.raw_data = Some(rd);
                    return vec![e];
                }
                return Vec::new(); // file readable, IP absent: final answer
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Vec::new()
    }
);

async fn cached_arp() -> Option<Vec<ArpRow>> {
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    {
        let guard = cache.lock().ok()?;
        if let Some((at, rows)) = guard.as_ref() {
            if at.elapsed().ok()? < Duration::from_secs(1) {
                return Some(rows.clone()); // guard ref deref
            }
        }
    }
    let rows = parse_proc_arp().await?;
    let _ = cache
        .lock()
        .ok()?
        .replace((SystemTime::now(), rows.clone()));
    Some(rows)
}

pub async fn parse_proc_arp() -> Option<Vec<ArpRow>> {
    let text = tokio::fs::read_to_string("/proc/net/arp").await.ok()?;
    Some(parse_arp_table(&text))
}

/// Pure /proc/net/arp body parse: only reachable (flags 0x2) entries
/// survive, MACs are lowercased, device comes from the 6th column. Short or
/// non-reachable lines are skipped, never fatal.
pub(crate) fn parse_arp_table(text: &str) -> Vec<ArpRow> {
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        if cols[2] != "0x2" {
            continue; // only reachable entries
        }
        rows.push(ArpRow {
            ip: cols[0].to_string(),
            mac: cols[3].to_ascii_lowercase(),
            device: cols[5].to_string(),
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_arp_table_keeps_reachable_rows_and_lowercases_macs() {
        let table = concat!(
            "IP address       HW type   Flags   HW address            Mask     Device\n",
            "192.0.2.5        0x1       0x2     AA:BB:CC:DD:EE:05    *        br-lan\n",
            "192.0.2.6        0x1       0x0     aa:bb:cc:dd:ee:06    *        br-lan\n",
            "truncated line\n",
        );
        let rows = parse_arp_table(table);
        assert_eq!(rows.len(), 1, "only the reachable (0x2) row survives");
        assert_eq!(rows[0].ip, "192.0.2.5");
        assert_eq!(rows[0].mac, "aa:bb:cc:dd:ee:05");
        assert_eq!(rows[0].device, "br-lan");
        assert!(parse_arp_table("").is_empty());
        assert!(parse_arp_table("header only\n").is_empty());
    }
}
