//! Capability probing and the prerequisite verdict for the agent-side eBPF
//! observer (#498) — the port of the center's machine
//! (`internal/service/scannerv2/ebpf/capability.go`, issue #493).
//!
//! One deliberate divergence from the center: the kernel floor is 5.8 here,
//! not 6.6. The center's loader (cilium/ebpf v0.22) can only attach via TCX
//! (kernel 6.6+); aya attaches via TCX on 6.6+ and falls back to the classic
//! netlink/clsact path on older kernels, so the issue's gate ("内核门槛 ≥5.8；
//! TCX（≥6.6）作为可选挂载路径，tc 回退") is what this module enforces.
//!
//! The red line, verbatim from the center: every eBPF problem degrades the
//! observer — it never crashes the agent and never blocks active scanning.

/// CAP_NET_ADMIN (tc qdisc/filter attach).
pub const CAP_NET_ADMIN: u32 = 12;
/// CAP_BPF (program load; kernel 5.8+).
pub const CAP_BPF: u32 = 39;

/// Minimum kernel for the observer: 5.8 (CAP_BPF era, classic TC attach).
pub const MIN_KERNEL: (u32, u32) = (5, 8);

/// What the platform probe gathered. All fields injectable for tests; the
/// real host read lives in [`host_probe`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProbeResult {
    /// `std::env::consts::OS` ("linux" on the targets that matter).
    pub goos: String,
    /// /proc/sys/kernel/osrelease, e.g. "6.6.144".
    pub release: String,
    /// /sys/kernel/btf/vmlinux exists. The TC program is CO-RE free, so BTF
    /// is optional: its absence is a warning, not a blocker.
    pub btf: bool,
    /// CapEff bitmask from /proc/self/status (0 when unreadable).
    pub cap_eff: u64,
    /// Effective uid (-1 when unreadable).
    pub euid: i32,
}

/// The verdict: `unsupported` entries are hard blockers (the observer must
/// not even attempt to load); `warnings` are proceed-anyway notes for the
/// operator; `missing_caps` names the privileges absent when unprivileged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Eval {
    pub unsupported: Vec<String>,
    pub warnings: Vec<String>,
    pub missing_caps: Vec<String>,
}

/// Read the real host. It never fails: unreadable sources surface as their
/// zero values and [`evaluate`] decides how much that blocks (off-Linux is
/// always unsupported; unreadable release/caps degrade to warnings).
pub fn host_probe() -> ProbeResult {
    ProbeResult {
        goos: std::env::consts::OS.to_string(),
        release: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        btf: std::path::Path::new("/sys/kernel/btf/vmlinux").exists(),
        cap_eff: parse_cap_eff(&std::fs::read_to_string("/proc/self/status").unwrap_or_default()),
        euid: parse_status_uid(
            &std::fs::read_to_string("/proc/self/status").unwrap_or_default(),
            "Uid:",
        ),
    }
}

/// The pure prerequisite evaluation (unit-tested on every platform).
pub fn evaluate(r: &ProbeResult) -> Eval {
    let mut ev = Eval::default();
    if r.goos != "linux" {
        ev.unsupported.push(format!(
            "eBPF requires Linux (host is {}); the passive observer stays off",
            r.goos
        ));
        return ev;
    }
    match parse_kernel_release(&r.release) {
        None => ev.warnings.push(format!(
            "kernel release {:?} unparsable; attempting to load anyway",
            r.release
        )),
        Some((major, minor)) if (major, minor) < MIN_KERNEL => ev.unsupported.push(format!(
            "kernel {} is older than {}.{}; upgrade the kernel to use the passive observer",
            r.release, MIN_KERNEL.0, MIN_KERNEL.1
        )),
        Some(_) => {}
    }
    if r.euid == -1 {
        ev.warnings.push(
            "cannot determine euid/capabilities from /proc/self/status; attempting to load anyway"
                .to_string(),
        );
    } else if r.euid != 0 {
        ev.missing_caps = missing_caps(r.cap_eff);
        if !ev.missing_caps.is_empty() {
            ev.unsupported.push(format!(
                "missing privileges: {} (run as root, or grant ambient caps — see docs/en/agent-rs.md)",
                ev.missing_caps.join(", ")
            ));
        }
    }
    if !r.btf {
        ev.warnings.push(
            "kernel BTF not found (/sys/kernel/btf/vmlinux); the TC program is CO-RE free so loading may still work"
                .to_string(),
        );
    }
    ev
}

/// Names of the required capabilities absent from the CapEff bitmask
/// (deterministic order).
pub fn missing_caps(cap_eff: u64) -> Vec<String> {
    let mut out = Vec::new();
    for (bit, name) in [(CAP_NET_ADMIN, "CAP_NET_ADMIN"), (CAP_BPF, "CAP_BPF")] {
        if cap_eff & (1 << bit) == 0 {
            out.push(name.to_string());
        }
    }
    out
}

/// Extract the major.minor pair from a kernel release string such as
/// "6.6.144", "5.15.0-rc7" or "6.18.40.1-microsoft-standard".
pub fn parse_kernel_release(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Extract the CapEff bitmask from /proc/self/status content. 0 when absent
/// or unparsable (the caller treats non-root + 0 as missing-everything,
/// which is the safe reading).
pub fn parse_cap_eff(status: &str) -> u64 {
    u64::from_str_radix(status_field(status, "CapEff:"), 16).unwrap_or(0)
}

/// Extract the first value of a "Uid:\t0\t0\t0\t0" style status line (the
/// effective uid). -1 when absent or unparsable.
pub fn parse_status_uid(status: &str, key: &str) -> i32 {
    let line = status_field(status, key);
    let value = line.split_whitespace().next().unwrap_or("");
    value.parse().unwrap_or(-1)
}

/// The trimmed remainder of the "Key:<value>" line ("" when absent).
fn status_field<'a>(status: &'a str, key: &str) -> &'a str {
    status
        .lines()
        .find(|l| l.starts_with(key))
        .map(|l| l.strip_prefix(key).unwrap_or("").trim())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux(release: &str, cap_eff: u64, euid: i32) -> ProbeResult {
        ProbeResult {
            goos: "linux".into(),
            release: release.into(),
            btf: true,
            cap_eff,
            euid,
        }
    }

    #[test]
    fn off_linux_is_unsupported() {
        let ev = evaluate(&ProbeResult {
            goos: "windows".into(),
            ..Default::default()
        });
        assert_eq!(ev.unsupported.len(), 1);
        assert!(ev.unsupported[0].contains("requires Linux"));
        assert!(ev.warnings.is_empty());
    }

    #[test]
    fn kernel_floor_is_5_8() {
        // 5.4 (pre CAP_BPF): blocked
        let ev = evaluate(&linux("5.4.0", 0, 0));
        assert!(
            ev.unsupported.iter().any(|u| u.contains("older than 5.8")),
            "{ev:?}"
        );
        // exactly 5.8: allowed
        let ev = evaluate(&linux("5.8.0", 0, 0));
        assert!(ev.unsupported.is_empty(), "{ev:?}");
        // 6.18 armhf rig: allowed
        let ev = evaluate(&linux("6.18.40.1-sunxi", 0, 0));
        assert!(ev.unsupported.is_empty());
        // center's floor (6.6, TCX-only loader) is NOT the agent's floor
        let ev = evaluate(&linux("6.1.0", 0, 0));
        assert!(ev.unsupported.is_empty(), "{ev:?}");
    }

    #[test]
    fn unparsable_release_degrades_to_warning() {
        let ev = evaluate(&linux("", 0, 0));
        assert!(ev.unsupported.is_empty());
        assert!(
            ev.warnings.iter().any(|w| w.contains("unparsable")),
            "{ev:?}"
        );
    }

    #[test]
    fn root_bypasses_the_cap_check() {
        let ev = evaluate(&linux("6.18.44", 0, 0));
        assert!(ev.missing_caps.is_empty());
        assert!(ev.unsupported.is_empty());
    }

    #[test]
    fn unprivileged_missing_caps_are_named_in_order() {
        let ev = evaluate(&linux("6.18.44", 0, 1000));
        assert_eq!(ev.missing_caps, vec!["CAP_NET_ADMIN", "CAP_BPF"]);
        assert!(ev
            .unsupported
            .iter()
            .any(|u| u.contains("missing privileges: CAP_NET_ADMIN, CAP_BPF")));
    }

    #[test]
    fn ambient_caps_satisfy_the_check() {
        let both = (1u64 << CAP_NET_ADMIN) | (1u64 << CAP_BPF);
        let ev = evaluate(&linux("6.18.44", both, 1000));
        assert!(ev.missing_caps.is_empty());
        assert!(ev.unsupported.is_empty());
    }

    #[test]
    fn unknown_uid_degrades_to_warning() {
        let ev = evaluate(&linux("6.18.44", 0, -1));
        assert!(ev.unsupported.is_empty());
        assert!(
            ev.warnings
                .iter()
                .any(|w| w.contains("cannot determine euid")),
            "{ev:?}"
        );
    }

    #[test]
    fn missing_btf_warns_but_proceeds() {
        let mut r = linux("6.18.44", 0, 0);
        r.btf = false;
        let ev = evaluate(&r);
        assert!(ev.unsupported.is_empty());
        assert!(
            ev.warnings.iter().any(|w| w.contains("CO-RE free")),
            "{ev:?}"
        );
    }

    #[test]
    fn kernel_release_parsing() {
        assert_eq!(parse_kernel_release("6.6.144"), Some((6, 6)));
        assert_eq!(parse_kernel_release("5.15.0-rc7"), Some((5, 15)));
        assert_eq!(
            parse_kernel_release("6.18.40.1-microsoft-standard"),
            Some((6, 18))
        );
        assert_eq!(parse_kernel_release("junk"), None);
        assert_eq!(parse_kernel_release("6"), None);
        assert_eq!(parse_kernel_release("x.y"), None);
    }

    #[test]
    fn cap_eff_and_uid_parsing() {
        let status = "Name:\tmibee-agent\nUmask:\t0022\nState:\tS (sleeping)\n\
                      Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
                      CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
                      CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), 0x1ffffffffff);
        assert_eq!(parse_status_uid(status, "Uid:"), 0);
        // absent fields → safe zero / -1
        assert_eq!(parse_cap_eff("Name:\tx\n"), 0);
        assert_eq!(parse_status_uid("Name:\tx\n", "Uid:"), -1);
        // non-numeric uid → -1
        assert_eq!(parse_status_uid("Uid:\tabc\t0\t0\t0\n", "Uid:"), -1);
    }
}
