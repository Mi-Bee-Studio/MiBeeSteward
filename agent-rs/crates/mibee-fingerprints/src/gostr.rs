//! Go-compatible string semantics.
//!
//! The Go classifier's byte-exactness depends on Go's `strings` helpers:
//! `ToLower`/`ToUpper` apply the Unicode **simple** (one-rune) case mapping
//! per rune, and `EqualFold` walks the simple-fold orbit. Rust's std
//! `str::to_lowercase` uses **full** case mapping (U+0130 `I-dotted` -> two
//! chars) and would diverge. The tables here are generated straight from
//! Go's `unicode` package (`difftest/gen_case_tables.go`), so parity is by
//! construction.

use crate::tables::{FOLD_REP, LOWER, UPPER};

fn table_lookup(table: &[(u32, u32)], c: char) -> Option<char> {
    let key = c as u32;
    table
        .binary_search_by_key(&key, |(k, _)| *k)
        .ok()
        .and_then(|i| char::from_u32(table[i].1))
}

fn fold_rep(c: char) -> u32 {
    let key = c as u32;
    match FOLD_REP.binary_search_by_key(&key, |(k, _)| *k) {
        Ok(i) => FOLD_REP[i].1,
        Err(_) => key,
    }
}

fn simple_lower(c: char) -> char {
    table_lookup(LOWER, c).unwrap_or(c)
}

fn simple_upper(c: char) -> char {
    table_lookup(UPPER, c).unwrap_or(c)
}

/// Per-rune simple lowercase, mirroring Go `strings.ToLower`.
pub fn go_to_lower(s: &str) -> String {
    s.chars().map(simple_lower).collect()
}

/// Per-rune simple uppercase, mirroring Go `strings.ToUpper`.
pub fn go_to_upper(s: &str) -> String {
    s.chars().map(simple_upper).collect()
}

/// Go `strings.EqualFold`: equal iff per-rune fold-orbit representatives
/// match (generated from Go's SimpleFold orbits).
pub fn go_equal_fold(a: &str, b: &str) -> bool {
    let mut ai = a.chars();
    let mut bi = b.chars();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) => {
                if x == y {
                    continue;
                }
                if fold_rep(x) != fold_rep(y) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// Go `strings.TrimSpace`.
pub fn go_trim_space(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_lower_upper() {
        assert_eq!(go_to_lower("SSH-2.0-OpenSSH"), "ssh-2.0-openssh");
        assert_eq!(go_to_upper("miwifi-r4a"), "MIWIFI-R4A");
    }

    #[test]
    fn simple_mapping_unlike_std() {
        // U+0130: Go simple lower = 'i'; std full lower is two chars.
        assert_eq!(go_to_lower("\u{0130}"), "i");
        // U+212A KELVIN SIGN: simple lower = 'k'.
        assert_eq!(go_to_lower("\u{212A}"), "k");
        // U+00DF sharp-s: Go simple upper keeps it unchanged.
        assert_eq!(go_to_upper("\u{00DF}"), "\u{00DF}");
    }

    #[test]
    fn equal_fold_cases() {
        assert!(go_equal_fold("MiWiFi", "miwifi"));
        assert!(go_equal_fold("MIWIFI", "miwifi"));
        assert!(!go_equal_fold("ssh", "ssj"));
        assert!(go_equal_fold("\u{212A}ey", "key"));
    }

    #[test]
    fn trim_space() {
        assert_eq!(go_trim_space("  x\r\n"), "x");
        assert_eq!(go_trim_space("\u{00a0}y\u{3000}"), "y");
    }
}
