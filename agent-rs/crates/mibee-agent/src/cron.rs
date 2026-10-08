//! Standard 5-field cron matching with robfig/cron v3 semantics — the parser
//! behind the Go agent's gocron scheduler (`gocron.CronJob(expr, false)`).
//! Fields: minute (0-59), hour (0-23), day-of-month (1-31), month (1-12 or
//! jan-dec), day-of-week (0-7 or sun-sat; 0 and 7 are both Sunday). Each
//! field accepts `*`, `* /n` steps, ranges `a-b`, lists `a,b,c`, `a-b/n`,
//! and `a/n` (= a..max every n). When BOTH dom and dow are restricted, a
//! minute matches when either matches (the classic Vixie cron OR rule).

use chrono::{DateTime, Datelike, Local, Timelike};

const MONTH_NAMES: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const DAY_NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

#[derive(Debug, Clone, PartialEq)]
pub struct CronSpec {
    minute: u64,
    hour: u64,
    dom: u64,
    mon: u64,
    dow: u64,
    dom_star: bool,
    dow_star: bool,
}

/// Parse one field into a bitset (bit i set = value i matches). Returns the
/// set plus whether the field was a bare `*` (unrestricted), which the
/// dom/dow OR rule needs to distinguish.
fn parse_field(field: &str, min: u32, max: u32, names: Option<(&[&str], u32)>) -> Option<(u64, bool)> {
    let mut bits: u64 = 0;
    let mut star = false;
    for part in field.split(',') {
        if part.is_empty() {
            return None;
        }
        let (range_part, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().ok()?),
            None => (part, 1),
        };
        if step == 0 {
            return None;
        }
        let (begin, end) = if range_part == "*" {
            if part == "*" {
                star = true;
            }
            (min, max)
        } else if let Some((a, b)) = range_part.split_once('-') {
            (parse_value(a, names)?, parse_value(b, names)?)
        } else {
            let v = parse_value(range_part, names)?;
            // robfig: `a/n` (single value with a step) means a..max every n.
            if part.contains('/') {
                (v, max)
            } else {
                (v, v)
            }
        };
        if begin < min || end > max || begin > end {
            return None;
        }
        let mut v = begin;
        while v <= end {
            bits |= 1u64 << v;
            v += step;
        }
    }
    Some((bits, star))
}

fn parse_value(tok: &str, names: Option<(&[&str], u32)>) -> Option<u32> {
    if let Some((table, base)) = names {
        if let Some(idx) = table.iter().position(|n| n.eq_ignore_ascii_case(tok)) {
            return Some(base + idx as u32);
        }
    }
    tok.parse::<u32>().ok()
}

impl CronSpec {
    pub fn parse(expr: &str) -> Option<CronSpec> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return None;
        }
        let (minute, _) = parse_field(fields[0], 0, 59, None)?;
        let (hour, _) = parse_field(fields[1], 0, 23, None)?;
        let (dom, dom_star) = parse_field(fields[2], 1, 31, None)?;
        let (mon, _) = parse_field(fields[3], 1, 12, Some((&MONTH_NAMES, 1)))?;
        // dow: 0-7 with 7 folding onto 0 (both Sunday).
        let (dow_raw, dow_star) = parse_field(fields[4], 0, 7, Some((&DAY_NAMES, 0)))?;
        let dow = dow_raw | (dow_raw >> 7);
        Some(CronSpec {
            minute,
            hour,
            dom,
            mon,
            dow,
            dom_star,
            dow_star,
        })
    }

    pub fn matches<Tz: chrono::TimeZone>(&self, now: &DateTime<Tz>) -> bool
    where
        DateTime<Tz>: Datelike + Timelike,
    {
        if self.minute & (1 << now.minute()) == 0 {
            return false;
        }
        if self.hour & (1 << now.hour()) == 0 {
            return false;
        }
        if self.mon & (1 << now.month()) == 0 {
            return false;
        }
        let dom_ok = self.dom & (1 << now.day()) != 0;
        let dow_ok = self.dow & (1 << now.weekday().num_days_from_sunday()) != 0;
        if !self.dom_star && !self.dow_star {
            dom_ok || dow_ok
        } else {
            dom_ok && dow_ok
        }
    }
}

/// True when `expr` is due at `now`. Invalid expressions are never due
/// (gocron rejects them at registration; here they just never fire).
pub fn cron_due(expr: &str, now: DateTime<Local>) -> bool {
    CronSpec::parse(expr)
        .map(|s| s.matches(&now))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    #[test]
    fn every_five_minutes() {
        let spec = CronSpec::parse("*/5 * * * *").unwrap();
        assert!(spec.matches(&at(2026, 10, 5, 3, 0)));
        assert!(spec.matches(&at(2026, 10, 5, 3, 55)));
        assert!(!spec.matches(&at(2026, 10, 5, 3, 3)));
    }

    #[test]
    fn hourly_shape() {
        let spec = CronSpec::parse("0 */2 * * *").unwrap();
        assert!(spec.matches(&at(2026, 10, 5, 4, 0)));
        assert!(!spec.matches(&at(2026, 10, 5, 5, 0)));
        assert!(!spec.matches(&at(2026, 10, 5, 4, 1)));
    }

    #[test]
    fn named_day_and_month() {
        // 2026-10-05 is a Monday.
        let spec = CronSpec::parse("0 3 * * mon").unwrap();
        assert!(spec.matches(&at(2026, 10, 5, 3, 0)));
        assert!(!spec.matches(&at(2026, 10, 6, 3, 0)));
        let spec = CronSpec::parse("0 3 1 jan,may *").unwrap();
        assert!(spec.matches(&at(2026, 1, 1, 3, 0)));
        assert!(spec.matches(&at(2026, 5, 1, 3, 0)));
        assert!(!spec.matches(&at(2026, 2, 1, 3, 0)));
    }

    #[test]
    fn dow_seven_is_sunday() {
        // 2026-10-04 is a Sunday.
        assert!(CronSpec::parse("0 3 * * 0").unwrap().matches(&at(2026, 10, 4, 3, 0)));
        assert!(CronSpec::parse("0 3 * * 7").unwrap().matches(&at(2026, 10, 4, 3, 0)));
    }

    #[test]
    fn dom_dow_or_when_both_restricted() {
        // "0 0 13 * 1": fires on the 13th AND every Monday, not only both.
        let spec = CronSpec::parse("0 0 13 * 1").unwrap();
        // 2026-10-13 is a Tuesday (dom matches).
        assert!(spec.matches(&at(2026, 10, 13, 0, 0)));
        // 2026-10-05 is a Monday, not the 13th (dow matches via OR).
        assert!(spec.matches(&at(2026, 10, 5, 0, 0)));
        // 2026-10-06 Tuesday, neither.
        assert!(!spec.matches(&at(2026, 10, 6, 0, 0)));
    }

    #[test]
    fn dom_dow_and_when_one_starred() {
        let spec = CronSpec::parse("0 0 13 * *").unwrap();
        assert!(spec.matches(&at(2026, 10, 13, 0, 0)));
        assert!(!spec.matches(&at(2026, 10, 5, 0, 0)));
        let spec = CronSpec::parse("0 0 * * 1").unwrap();
        assert!(spec.matches(&at(2026, 10, 5, 0, 0))); // Monday
        assert!(!spec.matches(&at(2026, 10, 13, 0, 0))); // Tuesday the 13th
    }

    #[test]
    fn ranges_lists_and_single_with_step() {
        let spec = CronSpec::parse("10-30/10 * * * *").unwrap();
        assert!(spec.matches(&at(2026, 10, 5, 0, 10)));
        assert!(spec.matches(&at(2026, 10, 5, 0, 20)));
        assert!(spec.matches(&at(2026, 10, 5, 0, 30)));
        assert!(!spec.matches(&at(2026, 10, 5, 0, 15)));
        assert!(!spec.matches(&at(2026, 10, 5, 0, 40))); // past the range end
        // lists
        let spec = CronSpec::parse("1,15,45 * * * *").unwrap();
        assert!(spec.matches(&at(2026, 10, 5, 0, 45)));
        assert!(!spec.matches(&at(2026, 10, 5, 0, 44)));
        // `a/n` = a..max every n (robfig): 20/15 → 20,35,50
        let spec = CronSpec::parse("20/15 * * * *").unwrap();
        assert!(spec.matches(&at(2026, 10, 5, 0, 35)));
        assert!(!spec.matches(&at(2026, 10, 5, 0, 50 + 1)));
    }

    #[test]
    fn rejects_bad_expressions() {
        assert!(CronSpec::parse("* * * *").is_none());
        assert!(CronSpec::parse("60 * * * *").is_none());
        assert!(CronSpec::parse("0 24 * * *").is_none());
        assert!(CronSpec::parse("0 0 0 * *").is_none()); // dom min is 1
        assert!(CronSpec::parse("0 0 * 13 *").is_none());
        assert!(CronSpec::parse("0 0 * * 8").is_none());
        assert!(CronSpec::parse("*/0 * * * *").is_none());
        assert!(!cron_due("garbage", Local::now()));
    }

    #[test]
    fn weekday_matches_midweek() {
        // 2026-10-07 is a Wednesday; 1-5 = mon-fri.
        let spec = CronSpec::parse("0 9 * * 1-5").unwrap();
        assert!(spec.matches(&at(2026, 10, 7, 9, 0)));
        assert!(!spec.matches(&at(2026, 10, 4, 9, 0))); // Sunday
    }
}
