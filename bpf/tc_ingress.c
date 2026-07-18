/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. You may use, modify, and redistribute it under
 * those terms; see LICENSE for the full text. A commercial license is available
 * for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

// tc_ingress.c — TC ingress eBPF program for passive service detection.
//
// Attached to network interfaces at the TC ingress hook (built via
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
// Build requirements: clang + llvm (>=14), kernel headers, libbpf-style
// vmlinux.h (generated via bpftool btf dump, see bpf/Makefile).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define EVENT_LEN 74

// event layout — must match decodeEvent() in observer_real.go.
struct event {
    __u32 src_ip;     // source IPv4 (network byte order)
    __u16 port;       // source port
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

// ONVIF WS-Discovery multicast address: 239.255.255.250 (big-endian).
#define ONVIF_MCAST_BE 0xEFFFFFFA

static __always_inline int has_prefix(const char *p, const char *prefix, int n) {
    #pragma unroll
    for (int i = 0; i < n; i++) {
        if (p[i] != prefix[i]) return 0;
    }
    return 1;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_UNSPEC;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_UNSPEC;
    if (ip->ihl < 5) return TC_ACT_UNSPEC;

    void *l4 = (void *)ip + (ip->ihl * 4);
    if (l4 + 8 > data_end) return TC_ACT_UNSPEC;

    __u32 src_ip = ip->saddr;
    __u16 src_port = 0;
    __u8 kind = 0;
    const char *payload = NULL;

    if (ip->protocol == 6) { // TCP
        struct tcphdr *tcp = l4;
        src_port = bpf_ntohs(tcp->source);
        payload = (void *)tcp + (tcp->doff * 4);
        if (payload + 8 > data_end) return TC_ACT_UNSPEC;
        if (has_prefix(payload, "SSH-", 4))        kind = KIND_SSH;
        else if (has_prefix(payload, "RTSP/1", 6)) kind = KIND_RTSP;
        else if (has_prefix(payload, "HTTP/1", 6)) kind = KIND_HTTP;
        else return TC_ACT_UNSPEC;
    } else if (ip->protocol == 17) { // UDP
        struct udphdr *udp = l4;
        __u16 dport = bpf_ntohs(udp->dest);
        __u16 sport = bpf_ntohs(udp->source);
        // WS-Discovery: traffic on port 3702 (either direction) to/from the
        // ONVIF multicast address.
        if ((dport == 3702 || sport == 3702) &&
            (src_ip == bpf_htonl(ONVIF_MCAST_BE) || ip->daddr == bpf_htonl(ONVIF_MCAST_BE))) {
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
    e->proto  = ip->protocol;
    e->kind   = kind;

    // Best-effort: copy a server/banner string fragment when available (TCP).
    if (payload && ip->protocol == 6) {
        int remaining = (data_end - payload);
        if (remaining > 64) remaining = 64;
        bpf_probe_read_kernel_str(e->server, 64, payload);
    }

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
