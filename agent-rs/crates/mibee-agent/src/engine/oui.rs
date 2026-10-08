//! Curated OUI vendor table: `<hex-prefix>\t<vendor>` lines, 6/7/9 hex
//! digits (MA-L / MA-M / MA-S), longest-prefix match, fixed probe order
//! 9 → 7 → 6 (Go internal/service/scannerv2/vendor/oui.go).

pub struct Oui {
    entries: Vec<(String, String)>, // (prefix-upper-hex, vendor)
}

impl Oui {
    pub fn parse(text: &str) -> Oui {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let line = if line.contains("//") { line.split("//").next().unwrap_or(line) } else { line };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // also accept raw IEEE "XX-XX-XX (hex)\t<vendor>" / "(base 16)" lines
            let (prefix, vendor) = match line.split_once('\t') {
                Some((a, b)) => (a, b),
                None => match line.split_once("  ") {
                    Some((a, b)) => (a, b),
                    None => continue,
                },
            };
            let prefix = prefix.replace(['-', ':', ' '], "").to_uppercase();
            let vendor = vendor.trim();
            // "(base 16)" continuation lines and empty vendors are skipped
            if vendor.is_empty() || vendor.starts_with('(') {
                continue;
            }
            // Go parses IEEE "XXXXXX (hex)" lines: prefix carries the suffix
            let prefix = prefix.split_whitespace().next().unwrap_or(&prefix).to_string();
            if prefix.len() != 6 && prefix.len() != 7 && prefix.len() != 9 {
                continue;
            }
            if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            entries.push((prefix, vendor.to_string()));
        }
        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len())); // longest first
        Oui { entries }
    }

    /// LookupFull: normalize the MAC (strip :.- and spaces, uppercase, keep
    /// up to 9 hex digits), longest-prefix match with fixed 9/7/6 probing.
    pub fn lookup_full(&self, mac: &str) -> Option<(String, String)> {
        let mut digits = String::with_capacity(9);
        for c in mac.chars() {
            if c == ':' || c == '-' || c == '.' || c == ' ' {
                continue;
            }
            let up = c.to_ascii_uppercase();
            if !up.is_ascii_hexdigit() || !up.is_ascii_digit() && !up.is_ascii_uppercase() {
                return None; // Go: any non-hex rune aborts
            }
            digits.push(up);
            if digits.len() >= 9 {
                break;
            }
        }
        if digits.len() < 6 {
            return None;
        }
        for len in [9usize, 7, 6] {
            if digits.len() < len {
                continue;
            }
            let probe = &digits[..len];
            for (p, v) in &self.entries {
                if p.len() == len && p == probe {
                    return Some((v.clone(), p.clone()));
                }
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Embedded curated copy — synced from the main repo's
/// configs/oui-curated.txt via `make sync-oui` equivalents; never hand-edit.
pub const EMBEDDED_OUI: &str = include_str!("../../assets/oui_curated.txt");

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# comment\n// another\nA4C11C\tAzureWave\n00044B\tNVIDIA\nF8D111\tDD-WRT\n000F23\t2E7E7E\n0050C2\tD-Link\nC4411E31C\tLongest\n";

    #[test]
    fn parses_and_lookup_longest_prefix() {
        let oui = Oui::parse(SAMPLE);
        assert_eq!(oui.len(), 6);
        // 9-digit MA-S beats any 6-digit interpretation
        let (vendor, prefix) = oui.lookup_full("C4:41:1E:31:C4:AA").unwrap();
        assert_eq!(vendor, "Longest");
        assert_eq!(prefix, "C4411E31C");
        // plain MA-L
        let (vendor, _) = oui.lookup_full("00:04:4B:12:34:56").unwrap();
        assert_eq!(vendor, "NVIDIA");
        // dotted / no-separator forms
        let (vendor, _) = oui.lookup_full("0004.4B99.99").unwrap();
        assert_eq!(vendor, "NVIDIA");
        let (vendor, _) = oui.lookup_full("a4c11c-aabbcc").unwrap();
        assert_eq!(vendor, "AzureWave");
    }

    #[test]
    fn bad_macs_rejected() {
        let oui = Oui::parse(SAMPLE);
        assert!(oui.lookup_full("").is_none());
        assert!(oui.lookup_full("00:04").is_none()); // < 6 digits
        assert!(oui.lookup_full("zz:04:4B:11:22:33").is_none());
    }

    #[test]
    fn embedded_table_loads() {
        let oui = Oui::parse(EMBEDDED_OUI);
        assert!(!oui.is_empty());
        // sanity: a Xiaomi-ecosystem prefix resolves
        let (vendor, _) = oui.lookup_full("64:09:80:11:22:33").unwrap();
        assert!(vendor.to_lowercase().contains("xiaomi"), "{vendor}");
    }
}
