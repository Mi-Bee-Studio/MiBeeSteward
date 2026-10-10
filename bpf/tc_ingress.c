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

#define EVENT_LEN 74

// event layout — must match decodeEvent() in event.go (shared with the stub
// build so the default CI tests cover the decoding).
struct event {
    __u32 src_ip;     // source IPv4 (network byte order)
    __u16 port;       // source port (host order)
    __u16 proto;      // L4 protocol (6=tcp, 17=udp)
    __u8  kind;       // kind* constant below
    __u8  _pad;
    char server[64];  // optional banner/server string
};

enum {
    KIND_SSH = 1,
    KIND_RTSP = 2,
    KIND_HTTP = 3,
    KIND_WSDISCOVERY = 4,
};

// Ring buffer map — consumed by userspace (ringbuf.Reader).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64 KiB
} events SEC(".maps");

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

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    // ---- L2: Ethernet header into a stack buffer -------------------------
    __u8 eth[14];
    if (bpf_skb_load_bytes(skb, 0, eth, sizeof(eth)) < 0) return TC_ACT_UNSPEC;
    if (eth[12] != 0x08 || eth[13] != 0x00) return TC_ACT_UNSPEC; // ethertype IPv4
    // Note: VLAN-tagged frames (802.1Q) are skipped; acceptable for passive
    // corroborating evidence.

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
    __u32 payload_len = 0;

    if (proto == 6) { // TCP
        __u8 tcph[20];
        if (bpf_skb_load_bytes(skb, 14 + 20, tcph, sizeof(tcph)) < 0) return TC_ACT_UNSPEC;
        __u8 doff = tcph[12] >> 4;
        if (doff < 5) return TC_ACT_UNSPEC;
        __u32 off = 14 + 20 + (doff * 4); // scalar arithmetic only
        if (bpf_skb_load_bytes(skb, off, payload, sizeof(payload)) < 0) return TC_ACT_UNSPEC;
        payload_len = sizeof(payload);

        if (has_prefix(payload, "SSH-", 4))        kind = KIND_SSH;
        else if (has_prefix(payload, "RTSP/1", 6)) kind = KIND_RTSP;
        else if (has_prefix(payload, "HTTP/1", 6)) kind = KIND_HTTP;
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

    // Banner fragment for TCP kinds: the stack buffer is already
    // zero-padded, so the copy is NUL-safe for userspace string handling.
    if (proto == 6 && payload_len == sizeof(payload)) {
        __builtin_memcpy(e->server, payload, sizeof(e->server));
    }

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
