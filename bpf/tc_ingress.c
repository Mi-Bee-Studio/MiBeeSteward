/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. You should use, modify, and redistribute it
 * under those terms; see LICENSE for the full text. A commercial license is
 * available for use cases the AGPL does not accommodate; see
 * LICENSE-COMMERCIAL.md.
 */

// tc_ingress.c — TC ingress eBPF program for passive service detection.
//
// Attached to network interfaces at the TCX ingress hook (built via
// `make build-with-ebpf` only). For every incoming packet it inspects the L4
// payload for known protocol magic prefixes and, on a match, emits an event to
// a ring buffer consumed by the Go loader.
//
// Detection rules (deliberately minimal — see docs/architecture.md):
//   1. UDP src/dst port 3702 to/from 239.255.255.250 → ONVIF WS-Discovery
//   2. TCP payload starting with "SSH-"   → SSH banner
//   3. TCP payload starting with "RTSP/1" → RTSP banner
//   4. TCP payload starting with "HTTP/1" → HTTP response banner
//
// The program is read-only observation: it never modifies or drops packets
// (returns TC_ACT_UNSPEC). It only emits metadata. False positives are
// acceptable here — the userspace classifier fuses this with active-probe
// evidence and applies confidence thresholds.
//
// VERIFIER PORTABILITY (#493/#494, rig-verified 2026-10-10): the program
// performs ZERO direct packet-pointer arithmetic. All packet bytes are read
// through bpf_skb_load_bytes into stack buffers and parsed there. Reason:
// variable-offset pointer arithmetic (e.g. l4 = ip + ihl*4, payload = tcp +
// doff*4) makes the verifier apply its unprivileged analysis ("pointer
// arithmetic prohibited for !root") on kernels where the loader runs with
// ambient CAP_BPF but a non-root euid — observed live on kernel 6.18.44
// (Armbian). Helper-based reads load fine in that configuration, which is
// the documented systemd drop-in deployment shape. The cost: packets with IP
// options (ihl != 5) are skipped — a negligible slice, and passive evidence
// is corroborating only.
//
// Build requirements: clang (>=14) only — the program is CO-RE free (stable
// UAPI types only, see bpf_standalone.h): no bpftool, no kernel BTF, no
// libbpf headers at build time, and it loads on kernels without BTF as well.

#include "bpf_standalone.h"

#define EVENT_LEN 124

// event layout (v3, #496) — must match decodeEvent() in event.go (shared with
// the stub build so the default CI tests cover the decoding). Variable-index
// stack writes are FORBIDDEN in this program: clang lowers them to
// `pointer |= scalar`, which the verifier rejects outright (seen live on
// 6.18). Every field below is filled by constant-index writes only; all
// string building (DNS label joining, opt55 decimal joining) happens in the
// Go decoder.
struct event {
    __u32 src_ip;       // source IPv4 (network byte order)
    __u16 port;         // source port (host order)
    __u16 proto;        // L4 protocol (6=tcp, 17=udp)
    __u8  kind;         // kind* constant below
    __u8  _pad;
    char server[64];    // banner / DHCP vendor class (<=32) / TLS SNI (<=32)
    char opt55_raw[12]; // DHCP option 55 raw bytes (first 12 request codes)
    char name_raw[32];  // mDNS query name, DNS wire format (<=32 bytes)
    __u8  opt55_len;    // valid bytes in opt55_raw, 0 = absent
    __u8  dhcp_type;    // DHCP message type (option 53), 0 = absent
    __u8  _pad2[4];     // pad sizeof(struct event) to EVENT_LEN
};

enum {
    KIND_SSH = 1,
    KIND_RTSP = 2,
    KIND_HTTP = 3,
    KIND_WSDISCOVERY = 4,
    KIND_DHCP = 5,
    KIND_TLS_SNI = 6,
    KIND_MDNS = 7,
    KIND_SSDP = 8,
    KIND_ARP = 9,   // ARP presence (#497): sender IP+MAC, op in dhcp_type
    KIND_ND = 10,   // IPv6 NS/NA/RS presence (#497): src IPv6 in server, MAC in opt55_raw
};

// Ring buffer map — consumed by userspace (ringbuf.Reader).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64 KiB
} events SEC(".maps");

// Presence throttle (#497): one sighting per (ip, mac, kind) per ~30s bucket.
// LRU so a broadcast storm cannot grow it — the kernel evicts cold entries at
// the 8192 cap and a re-sighting after eviction simply re-emits, which is the
// correct direction (presence is refreshed, never lost).
struct sighting_key {
    __u32 ip;        // sender IPv4 (network order); 0 for ND
    __u8  mac[6];    // sender MAC
    __u8  kind;      // KIND_ARP or KIND_ND
    __u8  _pad;
};
struct sighting_val {
    __u64 bucket;    // ktime_ns / 30s
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct sighting_key);
    __type(value, struct sighting_val);
} sighting_last SEC(".maps");

// sighting_throttled returns 1 (and records the sighting) when this (ip, mac,
// kind) was ALREADY emitted in the current 30s bucket, 0 when the sighting
// should proceed to the ring buffer.
static __always_inline int sighting_throttled(const struct sighting_key *k) {
    __u64 bucket = bpf_ktime_get_ns() / 30000000000ULL;
    struct sighting_val *v = bpf_map_lookup_elem(&sighting_last, k);
    if (v && v->bucket == bucket) {
        return 1;
    }
    struct sighting_val nv = { .bucket = bucket };
    bpf_map_update_elem(&sighting_last, k, &nv, BPF_ANY);
    return 0;
}

// ONVIF WS-Discovery multicast address bytes: 239.255.255.250 = ef ff ff fa.
#define ONVIF_MCAST_B0 0xef
#define ONVIF_MCAST_B1 0xff
#define ONVIF_MCAST_B2 0xff
#define ONVIF_MCAST_B3 0xfa

// has_prefix compares a stack buffer against a literal prefix. b is fully
// initialized by bpf_skb_load_bytes before the call, so the unrolled reads
// are verifier-safe (no uninitialized-stack access).
static __always_inline int has_prefix(const char *b, const char *prefix, int n) {
    #pragma unroll
    for (int i = 0; i < n; i++) {
        if (b[i] != prefix[i]) return 0;
    }
    return 1;
}

// be16_at reads a big-endian u16 from a stack buffer.
static __always_inline __u16 be16_at(const __u8 *b) {
    return (__u16)((b[0] << 8) | b[1]);
}

// ---------------------------------------------------------------------------
// Wire parsers for the #496 signatures. All reads go through
// bpf_skb_load_bytes at SCALAR offsets (no packet-pointer arithmetic, see the
// verifier-portability note up top), and every loop has a fixed bound the
// verifier can prove.

// parse_dhcp walks the DHCP option list (after the 236-byte bootp header and
// the 4-byte magic cookie) collecting option 53 (message type), 60 (vendor
// class -> vendor, up to 63 bytes) and 55 (parameter request list -> opt55 as
// comma-joined decimal, up to 47 bytes). Returns 0 when the packet is not a
// plausible DHCP message.
// parse_dhcp walks the DHCP option list header-by-header (constant 2-byte
// reads at scalar offsets) and takes ONE constant-width window read for each
// fingerprint field: vendor class 32B (option 60), parameter request list 12B
// (option 55), message type 1B (option 53). A window crossing the packet end
// fails the helper and that field is simply skipped - fields sit mid-list in
// practice and this is corroborating evidence. No variable-length reads, no
// variable-index writes, and the walk is a bounded non-unrolled loop: each of
// those breaks the verifier in its ambient-caps mode or explodes its state
// count past the 1M complexity limit (all seen live on 6.18).
static __always_inline int parse_dhcp(void *skb, __u32 off, char *vendor, char *opt55_out, __u8 *opt55_n, __u8 *msg_type) {
    __u8 bootp[4];
    if (bpf_skb_load_bytes(skb, off + 236, bootp, sizeof(bootp)) < 0) return 0;
    if (bootp[0] != 0x63 || bootp[1] != 0x82 || bootp[2] != 0x53 || bootp[3] != 0x63)
        return 0; // magic cookie mismatch

    __u32 pos = off + 240;
    for (int i = 0; i < 48; i++) {
        __u8 hdr[2];
        if (bpf_skb_load_bytes(skb, pos, hdr, sizeof(hdr)) < 0) break; // packet ended mid-list: keep what the walk collected
        if (hdr[0] == 0) { pos += 1; continue; }  // pad
        if (hdr[0] == 255) break;                  // end of options
        __u8 code = hdr[0], olen = hdr[1];
        if (code == 53 && olen >= 1) {
            __u8 v[1];
            if (bpf_skb_load_bytes(skb, pos + 2, v, sizeof(v)) < 0) break;
            *msg_type = v[0];
        } else if (code == 60 && olen >= 1) {
            // Fixed 32-byte window (constant-width reads only, see notes), then
            // predicated constant-index zeroing so the captured string ends at
            // the option's real length instead of bleeding into the next option.
            bpf_skb_load_bytes(skb, pos + 2, vendor, 32); // failure leaves zeros
            __u8 vn = olen; if (vn > 32) vn = 32;
            #pragma unroll
            for (int k = 0; k < 32; k++) {
                if (k >= vn) vendor[k] = 0;
            }
        } else if (code == 55 && olen >= 1) {
            bpf_skb_load_bytes(skb, pos + 2, opt55_out, 12);
            __u8 n = olen; if (n > 12) n = 12;
            *opt55_n = n;
        }
        pos += 2 + olen;
    }
    return *msg_type != 0 || vendor[0] != 0 || *opt55_n != 0;
}

// parse_tls_sni walks a TLS ClientHello looking for the server_name
// extension (type 0x0000) and copies the first hostname (up to 63 bytes)
// into out. Every length field is read with a bounded helper call and the
// walk is capped; a malformed or truncated handshake returns 0.
static __always_inline int parse_tls_sni(void *skb, __u32 off, char *out) {
    __u8 h[5];
    if (bpf_skb_load_bytes(skb, off, h, sizeof(h)) < 0) return 0;
    if (h[0] != 0x16) return 0;              // handshake record
    if (h[1] != 0x03) return 0;              // major version 3

    __u32 p = off + 5;                        // handshake header
    __u8 hs[4];
    if (bpf_skb_load_bytes(skb, p, hs, sizeof(hs)) < 0) return 0;
    if (hs[0] != 0x01) return 0;              // ClientHello
    p += 4 + 2;                               // handshake hdr + client version
    __u8 lens[1];
    // session id
    if (bpf_skb_load_bytes(skb, p, lens, 1) < 0) return 0;
    p += 1 + lens[0];
    // cipher suites
    __u8 two[2];
    if (bpf_skb_load_bytes(skb, p, two, 2) < 0) return 0;
    p += 2 + be16_at(two);
    // compression methods
    if (bpf_skb_load_bytes(skb, p, lens, 1) < 0) return 0;
    p += 1 + lens[0];
    // extensions total length
    if (bpf_skb_load_bytes(skb, p, two, 2) < 0) return 0;
    p += 2;

    #pragma unroll
    for (int i = 0; i < 12; i++) {
        __u8 ext[4];
        if (bpf_skb_load_bytes(skb, p, ext, sizeof(ext)) < 0) return 0;
        __u16 etype = be16_at(ext), elen = be16_at(ext + 2);
        if (etype != 0) { p += 4 + elen; continue; }
        // server_name: list_len(2) name_type(1) name_len(2)
        __u8 sni[5];
        if (bpf_skb_load_bytes(skb, p + 4, sni, sizeof(sni)) < 0) return 0;
        __u16 name_len = be16_at(sni + 3);
        if (name_len == 0 || name_len > 32) return 0;
        // Single constant-width window read (see the DHCP note): a failure
        // near the packet tail drops the field, not the packet. Zero-fill
        // past name_len so a short hostname does not bleed into the next
        // extension's bytes (predicated constant-index writes, verifier-safe).
        if (bpf_skb_load_bytes(skb, p + 9, out, 32) < 0) return 0;
        #pragma unroll
        for (int k = 0; k < 32; k++) {
            if (k >= name_len) out[k] = 0;
        }
        return 1;
    }
    return 0;
}

// parse_mdns_query captures the first 48 bytes of the query name section in
// DNS WIRE format (length-prefixed labels, verbatim). Validation and the
// dot-joined rendering happen in the Go decoder - the verifier forbids
// variable-index stack writes, so BPF captures raw bytes with constant-index
// writes only. Returns 0 unless the packet is a standard query (QR=0) with at
// least one question.
static __always_inline int parse_mdns_query(void *skb, __u32 off, char *name_raw) {
    __u8 hdr[6];
    if (bpf_skb_load_bytes(skb, off + 2, hdr, sizeof(hdr)) < 0) return 0;
    if ((hdr[0] & 0x80) != 0) return 0;       // QR=1: a response
    if (hdr[2] == 0 && hdr[3] == 0) return 0; // QDCOUNT == 0
    if (hdr[4] != 0 && hdr[5] != 0) { }       // ANCOUNT ignored

    // Predicated, break-less: a zero byte (read error, or the root label)
    // simply leaves the buffer zero-filled from that point, which is exactly
    // the terminator the Go label decoder stops at.
    // Single constant-width window read of the wire-format name right after
    // the 12-byte DNS header; the Go decoder walks the labels.
    if (bpf_skb_load_bytes(skb, off + 12, name_raw, 32) < 0) return 0;
    return name_raw[0] != 0;
}


SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    // ---- L2: Ethernet header into a stack buffer -------------------------
    __u8 eth[14];
    if (bpf_skb_load_bytes(skb, 0, eth, sizeof(eth)) < 0) return TC_ACT_UNSPEC;
    // Note: VLAN-tagged frames (802.1Q) are skipped; acceptable for passive
    // corroborating evidence.

    // ---- ARP presence (#497) ---------------------------------------------
    // ARP has no L3/L4; it is handled before the IPv4 path. Both requests and
    // replies carry the SENDER's IP+MAC — the presence pair we want. Sightings
    // are throttled per (sender ip, mac, kind) to a 30s bucket: a gratuitous-ARP
    // storm must not flood the ring buffer.
    if (eth[12] == 0x08 && eth[13] == 0x06) {
        __u8 arp[8];
        if (bpf_skb_load_bytes(skb, 14, arp, sizeof(arp)) < 0) return TC_ACT_UNSPEC;
        // htype(2) ptype(2) hlen(1) plen(1) op(2): Ethernet/IPv4 ARP only.
        if (arp[0] != 0x00 || arp[1] != 0x01) return TC_ACT_UNSPEC;
        if (arp[2] != 0x08 || arp[3] != 0x00) return TC_ACT_UNSPEC;
        if (arp[4] != 6 || arp[5] != 4) return TC_ACT_UNSPEC;

        struct sighting_key k = {};
        k.kind = KIND_ARP;
        if (bpf_skb_load_bytes(skb, 14 + 8, k.mac, 6) < 0) return TC_ACT_UNSPEC;
        __u32 spa;
        if (bpf_skb_load_bytes(skb, 14 + 14, &spa, 4) < 0) return TC_ACT_UNSPEC;
        if (spa == 0) return TC_ACT_UNSPEC; // 0.0.0.0 senders (DAD probes) carry no identity
        k.ip = spa;
        if (sighting_throttled(&k)) return TC_ACT_UNSPEC;

        struct event *e = bpf_ringbuf_reserve(&events, EVENT_LEN, 0);
        if (!e) return TC_ACT_UNSPEC;
        __builtin_memset(e, 0, EVENT_LEN);
        e->src_ip  = spa;
        e->kind    = KIND_ARP;
        e->opt55_len = 6;
        __builtin_memcpy(e->opt55_raw, k.mac, 6);
        e->dhcp_type = arp[6] == 0x00 && arp[7] == 0x01 ? 1 : 2; // 1=request, 2=reply
        bpf_ringbuf_submit(e, 0);
        return TC_ACT_UNSPEC;
    }

    // ---- IPv6 ND presence (#497) ------------------------------------------
    // NS(135)/NA(136)/RS(133) prove a live IPv6 speaker. The event carries the
    // sender's link-local (or global) source address raw in server[16] and the
    // Ethernet source MAC in opt55_raw; the IPv4 src_ip field stays 0.
    if (eth[12] == 0x86 && eth[13] == 0xdd) {
        __u8 ip6h[8];
        if (bpf_skb_load_bytes(skb, 14, ip6h, sizeof(ip6h)) < 0) return TC_ACT_UNSPEC;
        if ((ip6h[0] >> 4) != 6) return TC_ACT_UNSPEC;              // version
        if (ip6h[6] != 58) return TC_ACT_UNSPEC;                    // next header ICMPv6
        __u8 icmp6[2];
        if (bpf_skb_load_bytes(skb, 14 + 40, icmp6, sizeof(icmp6)) < 0) return TC_ACT_UNSPEC;
        if (icmp6[0] != 133 && icmp6[0] != 135 && icmp6[0] != 136) return TC_ACT_UNSPEC;

        struct sighting_key k = {};
        k.kind = KIND_ND;
        __builtin_memcpy(k.mac, eth + 6, 6);
        if (sighting_throttled(&k)) return TC_ACT_UNSPEC;

        // Read the sender IPv6 into a stack buffer BEFORE reserving the ring
        // slot: a failed read must not return with the reservation held (the
        // verifier rejects exactly that as a reference leak).
        char ipv6[16] = {};
        if (bpf_skb_load_bytes(skb, 14 + 8, ipv6, 16) < 0) return TC_ACT_UNSPEC;

        struct event *e = bpf_ringbuf_reserve(&events, EVENT_LEN, 0);
        if (!e) return TC_ACT_UNSPEC;
        __builtin_memset(e, 0, EVENT_LEN);
        e->kind    = KIND_ND;
        e->proto   = 58; // ICMPv6
        e->opt55_len = 6;
        __builtin_memcpy(e->opt55_raw, k.mac, 6);
        __builtin_memcpy(e->server, ipv6, 16);
        e->dhcp_type = icmp6[0];
        bpf_ringbuf_submit(e, 0);
        return TC_ACT_UNSPEC;
    }

    if (eth[12] != 0x08 || eth[13] != 0x00) return TC_ACT_UNSPEC; // ethertype IPv4

    // ---- L3: fixed 20-byte IPv4 header ------------------------------------
    __u8 iph[20];
    if (bpf_skb_load_bytes(skb, 14, iph, sizeof(iph)) < 0) return TC_ACT_UNSPEC;
    if ((iph[0] >> 4) != 4) return TC_ACT_UNSPEC;              // version
    if ((iph[0] & 0x0f) != 5) return TC_ACT_UNSPEC;            // ihl: skip IP options

    __u8 proto = iph[9];
    __u32 src_ip, dst_ip;
    __builtin_memcpy(&src_ip, iph + 12, 4);
    __builtin_memcpy(&dst_ip, iph + 16, 4);

    __u16 src_port = 0;
    __u8 kind = 0;
    char payload[64] = {};
    char server[64] = {};   // parsed identity string (SNI / vendor class)
    char opt55_raw[12] = {};
    char name_raw[32] = {};
    __u8 opt55_len = 0;
    __u8 dhcp_type = 0;

    if (proto == 6) { // TCP
        __u8 tcph[20];
        if (bpf_skb_load_bytes(skb, 14 + 20, tcph, sizeof(tcph)) < 0) return TC_ACT_UNSPEC;
        __u8 doff = tcph[12] >> 4;
        if (doff < 5) return TC_ACT_UNSPEC;
        __u32 off = 14 + 20 + (doff * 4); // scalar arithmetic only
        if (bpf_skb_load_bytes(skb, off, payload, sizeof(payload)) < 0) return TC_ACT_UNSPEC;

        if (has_prefix(payload, "SSH-", 4))        kind = KIND_SSH;
        else if (has_prefix(payload, "RTSP/1", 6)) kind = KIND_RTSP;
        else if (has_prefix(payload, "HTTP/1", 6)) kind = KIND_HTTP;
        else if (parse_tls_sni(skb, off, server)) { kind = KIND_TLS_SNI; }
        else return TC_ACT_UNSPEC;

        src_port = be16_at(tcph);
    } else if (proto == 17) { // UDP
        __u8 udph[8];
        if (bpf_skb_load_bytes(skb, 14 + 20, udph, sizeof(udph)) < 0) return TC_ACT_UNSPEC;
        __u16 sport = be16_at(udph);
        __u16 dport = be16_at(udph + 2);
        __u8 *sip = (__u8 *)&src_ip;
        __u8 *dip = (__u8 *)&dst_ip;
        // WS-Discovery: port 3702 (either direction) to/from the ONVIF group.
        int mcast_src = sip[0] == ONVIF_MCAST_B0 && sip[1] == ONVIF_MCAST_B1 &&
                        sip[2] == ONVIF_MCAST_B2 && sip[3] == ONVIF_MCAST_B3;
        int mcast_dst = dip[0] == ONVIF_MCAST_B0 && dip[1] == ONVIF_MCAST_B1 &&
                        dip[2] == ONVIF_MCAST_B2 && dip[3] == ONVIF_MCAST_B3;
        if ((dport == 3702 || sport == 3702) && (mcast_src || mcast_dst)) {
            kind = KIND_WSDISCOVERY;
            src_port = sport;
        } else if (sport == 68 || dport == 67 || sport == 67 || dport == 68) {
            // DHCP (#496/#508): vendor class (opt 60), parameter request list
            // (opt 55) and message type (opt 53) are the fingerprint fields.
            if (!parse_dhcp(skb, 14 + 20 + 8, server, opt55_raw, &opt55_len, &dhcp_type))
                return TC_ACT_UNSPEC;
            kind = KIND_DHCP;
            src_port = sport;
        } else if (dport == 5353 || sport == 5353) {
            // mDNS: capture the first query name of a standard query (#496).
            if (!parse_mdns_query(skb, 14 + 20 + 8, name_raw))
                return TC_ACT_UNSPEC;
            kind = KIND_MDNS;
            src_port = sport;
        } else if (dport == 1900 || sport == 1900) {
            // SSDP: method/prefix presence only (#496) — header deep-scan
            // stays with the active probe + description fetch.
            __u8 head[1];
            if (bpf_skb_load_bytes(skb, 14 + 20 + 8, head, sizeof(head)) < 0)
                return TC_ACT_UNSPEC;
            if (head[0] != 'M' && head[0] != 'N' && head[0] != 'H')
                return TC_ACT_UNSPEC;
            kind = KIND_SSDP;
            src_port = sport;
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    struct event *e = bpf_ringbuf_reserve(&events, EVENT_LEN, 0);
    if (!e) return TC_ACT_UNSPEC;

    __builtin_memset(e, 0, EVENT_LEN);
    e->src_ip = src_ip;
    e->port   = src_port;
    e->proto  = proto;
    e->kind   = kind;

    // Banner fragment for TCP banner kinds: the stack buffer is already
    // zero-padded, so the copy is NUL-safe for userspace string handling.
    if (kind == KIND_SSH || kind == KIND_RTSP || kind == KIND_HTTP) {
        __builtin_memcpy(e->server, payload, sizeof(e->server));
    }
    // Parsed identity fields (#496): TLS SNI / DHCP vendor class / mDNS query
    // land in server; opt55 + message type carry the DHCP fingerprint tail.
    if (server[0] != 0) {
        __builtin_memcpy(e->server, server, sizeof(e->server));
    }
    
    __builtin_memcpy(e->opt55_raw, opt55_raw, sizeof(e->opt55_raw));
    __builtin_memcpy(e->name_raw, name_raw, sizeof(e->name_raw));
    e->opt55_len = opt55_len;
    e->dhcp_type = dhcp_type;

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_UNSPEC;
}


char LICENSE[] SEC("license") = "GPL";
