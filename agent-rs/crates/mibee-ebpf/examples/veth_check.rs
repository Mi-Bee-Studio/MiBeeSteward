//! Local/rig diagnostic for the aya observer chain (#498): creates a veth
//! pair, starts the Observer on one end, injects known frames (ARP reply +
//! DHCP REQUEST with the Android vendor class + mDNS query) on the other,
//! and prints every event that reaches the sink. Run as root on Linux:
//!
//! ```text
//! cargo build --features loader --example veth_check
//! sudo ./target/debug/examples/veth_check
//! ```
//!
//! If events print, the whole kernel->ringbuf->aya-drain chain works and any
//! remaining break is in the consumer wiring above this crate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mibee_ebpf::event::{Event, Kind};
use mibee_ebpf::observer::{Observer, ObserverConfig};

const VETH_A: &str = "mibee-vc-a";
const VETH_B: &str = "mibee-vc-b";

fn sh(args: &[&str]) {
    let _ = std::process::Command::new(args[0])
        .args(&args[1..])
        .status();
}

fn main() {
    sh(&["ip", "link", "del", VETH_A]); // stale pair from a previous run
    sh(&[
        "ip", "link", "add", VETH_A, "type", "veth", "peer", "name", VETH_B,
    ]);
    sh(&["ip", "link", "set", VETH_A, "up"]);
    sh(&["ip", "link", "set", VETH_B, "up"]);

    let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
    let got = Arc::new(AtomicBool::new(false));
    let sink = {
        let events = Arc::clone(&events);
        let got = Arc::clone(&got);
        Arc::new(move |ev: Event| {
            got.store(true, Ordering::SeqCst);
            println!(
                "EVENT kind={:?} ip={} mac={} server={:?} opt55={:?} query={:?}",
                ev.kind, ev.ip, ev.mac, ev.server, ev.opt55, ev.query
            );
            events.lock().unwrap().push(ev);
        })
    };

    let mut observer = match Observer::start(
        ObserverConfig {
            interfaces: vec![VETH_A.to_string()],
        },
        sink,
    ) {
        Ok(o) => o,
        Err(reason) => {
            eprintln!("observer failed to start: {reason}");
            sh(&["ip", "link", "del", VETH_A]);
            std::process::exit(1);
        }
    };

    // Tap ingress DURING the injections: wire truth for every frame.
    let sniffer = std::thread::spawn(sniff_once);
    std::thread::sleep(Duration::from_millis(500));
    println!("-- injecting ARP reply");
    inject(&arp_reply_frame());
    std::thread::sleep(Duration::from_millis(300));
    println!("-- injecting DHCP REQUEST (android-dhcp-13)");
    inject(&dhcp_request_frame());
    std::thread::sleep(Duration::from_millis(300));
    println!("-- injecting mDNS query");
    inject(&mdns_query_frame());
    let _ = sniffer.join();
    // Hold everything alive so bpftool can inspect this load's maps/program
    // from outside (map dump decides: throttle-key present = program ran and
    // passed the gate for our frames; absent = the program never got there).
    println!("-- holding 12s for external bpftool inspection");
    std::thread::sleep(Duration::from_secs(12));
    for _ in 0..100 {
        if got.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(500)); // drain the rest
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    observer.stop();

    let events = events.lock().unwrap();
    let kinds: Vec<Option<Kind>> = events.iter().map(|e| e.kind).collect();
    println!("-- collected {} events: {:?}", events.len(), kinds);
    let ok = kinds.contains(&Some(Kind::ArpSighting))
        && kinds.contains(&Some(Kind::Dhcp))
        && kinds.contains(&Some(Kind::Mdns));
    sh(&["ip", "link", "del", VETH_A]);
    if ok {
        println!("PASS: arp + dhcp + mdns all reached userspace");
    } else {
        println!("FAIL: expected arp+dhcp+mdns kinds");
        std::process::exit(2);
    }
}

// ---- raw AF_PACKET injection (libc via musl linkage, no extra deps) ----

#[repr(C)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn sendto(
        fd: i32,
        buf: *const u8,
        len: usize,
        flags: i32,
        addr: *const SockaddrLl,
        alen: u32,
    ) -> isize;
    fn close(fd: i32) -> i32;
    fn if_nametoindex(name: *const u8) -> u32;
}

fn inject(frame: &[u8]) {
    const AF_PACKET: i32 = 17;
    const SOCK_RAW: i32 = 3;
    unsafe {
        let fd = socket(AF_PACKET, SOCK_RAW, 0);
        if fd < 0 {
            eprintln!("raw socket failed");
            return;
        }
        let mut name = VETH_B.as_bytes().to_vec();
        name.push(0);
        let ifindex = if_nametoindex(name.as_ptr()) as i32;
        let addr = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: 0x0008, // htons(ETH_P_IP)
            sll_ifindex: ifindex,
            sll_hatype: 1, // ARPHRD_ETHER
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0xff; 8],
        };
        let rc = sendto(
            fd,
            frame.as_ptr(),
            frame.len(),
            0,
            &addr,
            std::mem::size_of::<SockaddrLl>() as u32,
        );
        println!("   sendto rc={rc} ifindex={ifindex} len={}", frame.len());
        close(fd);
    }
}

/// Debug: tap VETH_A ingress with a second raw socket and print what the
/// interface actually receives (ethertype + first bytes).
fn sniff_once() {
    const AF_PACKET: i32 = 17;
    const SOCK_RAW: i32 = 3;
    unsafe {
        let fd = socket(AF_PACKET, SOCK_RAW, 0x0300); // htons(ETH_P_ALL)
        if fd < 0 {
            eprintln!("sniff socket failed");
            return;
        }
        let mut name = VETH_A.as_bytes().to_vec();
        name.push(0);
        let ifindex = if_nametoindex(name.as_ptr());
        let addr = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: 0x0300,
            sll_ifindex: ifindex as i32,
            sll_hatype: 1,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // bind via sendto-less path: use bind through libc
        extern "C" {
            fn bind(fd: i32, addr: *const SockaddrLl, len: u32) -> i32;
            fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
        }
        if bind(fd, &addr, std::mem::size_of::<SockaddrLl>() as u32) < 0 {
            eprintln!("sniff bind failed");
            close(fd);
            return;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        while std::time::Instant::now() < deadline {
            let mut buf = [0u8; 128];
            let n = recv(fd, buf.as_mut_ptr(), buf.len(), 0);
            if n > 0 {
                let n = n as usize;
                let hex: String = buf[..n.min(16)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!("   SNIFF len={n} first16={hex}");
            }
        }
        close(fd);
    }
}

// ---- frame builders (mirror bpf/tc_ingress.c expectations) ----

const SRC_MAC: [u8; 6] = [0x02, 0x81, 0x48, 0x4e, 0xd5, 0x99];

fn eth_frame(payload: &[u8], ethertype: [u8; 2]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(&SRC_MAC);
    f.extend_from_slice(&ethertype);
    f.extend_from_slice(payload);
    f
}

/// ARP REPLY: sender 192.0.2.50 @ 02:81:48:4e:d5:99.
fn arp_reply_frame() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0, 1, 8, 6, 6, 4, 0, 2]); // htype ptype hlen plen op=reply
    p.extend_from_slice(&SRC_MAC);
    p.extend_from_slice(&[192, 0, 2, 50]); // sender IP
    p.extend_from_slice(&[0xff; 6]); // target MAC
    p.extend_from_slice(&[192, 0, 2, 1]); // target IP
    eth_frame(&p, [0x08, 0x06])
}

fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum 0 (allowed for IPv4 UDP)
    udp.extend_from_slice(payload);
    let total = (20 + udp.len()) as u16;
    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0, 0]);
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0x49, 0x98, 0, 0]);
    ip.extend_from_slice(&[64, 17, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let mut f = eth_frame(&ip, [0x08, 0x00]);
    f.extend_from_slice(&udp);
    f
}

/// DHCP REQUEST: option 60 android-dhcp-13, option 55 Android list.
fn dhcp_request_frame() -> Vec<u8> {
    let mut b = Vec::with_capacity(300);
    b.extend_from_slice(&[1, 1, 6, 0]);
    b.extend_from_slice(&[0x49, 0x82, 0x53, 0x63]);
    b.extend_from_slice(&[0x80, 0, 0, 0]);
    b.extend_from_slice(&[0; 12]);
    b.extend_from_slice(&SRC_MAC);
    b.extend_from_slice(&[0; 10]);
    b.extend_from_slice(&[0; 64 + 128]);
    b.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    b.extend_from_slice(&[53, 1, 3]); // REQUEST
    b.extend_from_slice(&[60, 14]);
    b.extend_from_slice(b"android-dhcp-13");
    b.extend_from_slice(&[55, 10, 1, 33, 3, 6, 15, 26, 28, 51, 58, 59]);
    b.push(255);
    while b.len() < 300 {
        b.push(0);
    }
    udp4([192, 0, 2, 50], [255, 255, 255, 255], 68, 67, &b)
}

/// mDNS standard query for rig-sensor._tcp.local.
fn mdns_query_frame() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    q.push(10);
    q.extend_from_slice(b"rig-sensor");
    q.push(4);
    q.extend_from_slice(b"_tcp");
    q.push(5);
    q.extend_from_slice(b"local");
    q.push(0);
    q.extend_from_slice(&[0, 12, 0, 1]); // PTR, IN
    udp4([192, 0, 2, 50], [224, 0, 0, 251], 5353, 5353, &q)
}
