//! The aya observer: loads the shared TC ingress program, attaches it to the
//! configured interfaces and drains the `events` ring buffer into a channel
//! (#498). Compiled only on Linux with `feature = "loader"` — everywhere
//! else the module does not exist, which is what keeps default builds free
//! of aya and byte-identical.
//!
//! Degrade contract (center parity, #493): every environmental problem —
//! unsupported host, missing privileges, load or attach failure — surfaces as
//! an `Err(reason)` from [`Observer::start`] (or a warn line for partial
//! attach) and the observer stays off. The agent keeps running; active
//! probing is unaffected. Nothing here may panic on environmental input.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use aya::maps::RingBuf;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::EbpfLoader;

use crate::capability::{evaluate, host_probe};
use crate::event::{self, Event};

/// The kernel object, byte-identical to the copy the Go center embeds
/// (pinned together by the drift test and `make check-agent-rs-assets`).
pub static TC_INGRESS_OBJ: &[u8] = include_bytes!("../ebpf/tc_ingress.bpfel.o");

/// How long the drain thread sleeps when the ring buffer is empty. Passive
/// evidence has no latency contract; 50 ms keeps the thread invisible.
const DRAIN_POLL_MS: u64 = 50;

pub struct ObserverConfig {
    /// Interfaces to attach to; empty = every up, non-loopback interface.
    pub interfaces: Vec<String>,
}

/// Where decoded events land. Called from the drain thread (plain sync
/// context — no async runtime coupling in this crate); the agent side
/// bridges into its tokio tasks.
pub type EventSink = Arc<dyn Fn(Event) + Send + Sync>;

/// A running observer: holds the loaded objects alive (their fds keep the
/// programs in the kernel; aya detaches the managed links and unloads on
/// drop) plus the drain thread handle.
pub struct Observer {
    /// Never read on purpose: dropping it unloads the programs and detaches
    /// the managed links (aya teardown), so it must outlive the drain thread.
    #[allow(dead_code)]
    ebpf: aya::Ebpf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Observer {
    /// Capability-gate, load, attach, and start draining. `on_event` receives
    /// every decoded event for as long as the observer lives.
    pub fn start(cfg: ObserverConfig, on_event: EventSink) -> Result<Observer, String> {
        // 1. Prerequisites — hard blockers end here without touching the
        //    kernel at all (Go start() parity).
        let rep = host_probe();
        let verdict = evaluate(&rep);
        for w in &verdict.warnings {
            eprintln!("ebpf: observer warning: {w}");
        }
        if !verdict.unsupported.is_empty() {
            return Err(verdict.unsupported.join("; "));
        }

        // 2. Load the shared object. aya parses the standard clang ELF
        //    (BTF .maps definitions included); failures degrade.
        let mut ebpf = EbpfLoader::new()
            .load(TC_INGRESS_OBJ)
            .map_err(|e| format!("load TC program: {e}"))?;
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_ingress")
            .ok_or_else(|| "program tc_ingress missing from the object".to_string())?
            .try_into()
            .map_err(|e| format!("program tc_ingress is not a SCHED_CLS: {e}"))?;
        prog.load().map_err(|e| format!("load program: {e}"))?;

        // 3. Attach. aya picks TCX on >= 6.6 and the classic netlink/clsact
        //    path on older kernels — exactly the issue's mount matrix. The
        //    clsact pre-add is ignored where TCX applies and is idempotent
        //    (EEXIST) where it is needed. Per-interface failures are
        //    tolerated: attach what works; zero attachments fails.
        let ifaces = if cfg.interfaces.is_empty() {
            non_loopback_up_interfaces()
        } else {
            cfg.interfaces
        };
        if ifaces.is_empty() {
            return Err("no up, non-loopback interface found to attach to".to_string());
        }
        let mut links = Vec::new();
        let mut attached = Vec::new();
        for iface in &ifaces {
            let _ = tc::qdisc_add_clsact(iface); // no-op for TCX / when present
            match prog.attach(iface, TcAttachType::Ingress) {
                Ok(link) => {
                    links.push(link);
                    attached.push(iface.clone());
                    eprintln!("ebpf: TC attached iface={iface}");
                }
                Err(e) => {
                    eprintln!("ebpf: TC attach failed for interface iface={iface} error={e}");
                }
            }
        }
        // The link ids are tracked by the program itself (aya detaches them
        // when the objects drop); only the count decides the verdict here.
        drop(links);
        if attached.is_empty() {
            return Err(
                "no interface could host the TC program (kernel < 5.8? CAP_NET_ADMIN missing? interface down?)"
                    .to_string(),
            );
        }
        if attached.len() < ifaces.len() {
            eprintln!(
                "ebpf: observer degraded: attached {}/{} interfaces",
                attached.len(),
                ifaces.len()
            );
        }

        // 4. Ring-buffer drain on its own thread: RingBuf::next is poll-style
        //    (mmap reads cannot fail), so an idle sleep keeps it off the CPU.
        //    Events hop into the agent's async world through the sync sink.
        let map = ebpf
            .take_map("events")
            .ok_or_else(|| "map events missing from the object".to_string())?;
        let mut rb = RingBuf::try_from(map).map_err(|e| format!("open ring buffer: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("mibee-ebpf-drain".into())
            .spawn(move || loop {
                while let Some(item) = rb.next() {
                    let data: &[u8] = &item;
                    if let Some(ev) = event::decode(data) {
                        on_event(ev);
                    }
                }
                if thread_stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(DRAIN_POLL_MS));
            })
            .map_err(|e| format!("spawn drain thread: {e}"))?;

        eprintln!(
            "ebpf: passive observer active kernel={} btf={} interfaces={}",
            rep.release,
            rep.btf,
            attached.join(",")
        );
        Ok(Observer {
            ebpf,
            stop,
            thread: Some(thread),
        })
    }

    /// Stop the drain thread. The TC programs detach and unload when the
    /// observer (and its `Ebpf` objects) drops; aya manages the teardown.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Up, non-loopback interface names (the default attach set) — read from
/// /sys/class/net without a dependency: `flags` holds the ioctl bit mask in
/// hex ("0x1003"); IFF_UP is bit 0.
fn non_loopback_up_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        let flags = std::fs::read_to_string(entry.path().join("flags"))
            .ok()
            .and_then(|f| u64::from_str_radix(f.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        if flags & 0x1 != 0 {
            out.push(name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded object must parse as a standard BPF ELF with the two
    /// maps and the sched_cls program, WITHOUT any privileges — parsing is
    /// pure userspace. This is the continuous guard that aya understands
    /// what bpf2go emitted (the load-into-kernel half is rig-verified).
    #[test]
    fn object_parses_with_aya() {
        let mut ebpf = EbpfLoader::new()
            .load(TC_INGRESS_OBJ)
            .expect("aya parses the object");
        let maps: Vec<String> = ebpf.maps().map(|(n, _)| n.to_string()).collect();
        assert!(maps.iter().any(|m| m == "events"), "maps: {maps:?}");
        assert!(maps.iter().any(|m| m == "sighting_last"), "maps: {maps:?}");
        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_ingress")
            .expect("program tc_ingress")
            .try_into()
            .expect("sched_cls program");
        let _ = prog;
    }
}
