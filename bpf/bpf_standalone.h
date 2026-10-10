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

/*
 * bpf_standalone.h — self-contained BPF program support header (#494).
 *
 * The TC programs in this directory deliberately use ONLY stable UAPI types
 * (ethhdr/iphdr/tcphdr/udphdr/__sk_buff virtual fields) and a small set of
 * stable helpers. They never touch kernel-internal structures, so they need
 * no CO-RE relocations and therefore no kernel BTF — neither at build time
 * nor at load time. This header provides everything such a program needs:
 *
 *   - fixed-width typedefs,
 *   - byte-order macros (bpf_htons family),
 *   - map declaration macros (SEC/__uint/__type/__array),
 *   - the UAPI struct layouts,
 *   - extern declarations for the helpers used (the loader resolves them by
 *     name, exactly as libbpf's bpf_helpers.h does).
 *
 * Benefit: compiling a program here requires ONLY clang (>=14) on ANY host
 * OS — no bpftool, no /sys/kernel/btf/vmlinux, no libbpf headers, no Linux
 * headers. Loading works on kernels without BTF too, which widens the set
 * of deployable targets (older OpenWrt builds ship without
 * CONFIG_DEBUG_INFO_BTF). Do NOT add kernel-internal type accesses to these
 * programs: that would silently reintroduce the CO-RE/BTF dependency.
 */

#ifndef MIBEE_BPF_STANDALONE_H
#define MIBEE_BPF_STANDALONE_H

/* ------------------------------------------------------------------ */
/* Fixed-width typedefs (as the kernel UAPI and vmlinux.h define them)  */
/* ------------------------------------------------------------------ */

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;

/* ------------------------------------------------------------------ */
/* Byte order (subset of libbpf bpf_endian.h semantics)                 */
/* ------------------------------------------------------------------ */

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD 1
#define bpf_htons(x) ((__be16)__builtin_bswap16(x))
#define bpf_ntohs(x) (__builtin_bswap16(x))
#define bpf_htonl(x) ((__be32)__builtin_bswap32(x))
#define bpf_ntohl(x) (__builtin_bswap32(x))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD 1
#define bpf_htons(x) ((__be16)(x))
#define bpf_ntohs(x) (__u16)(x)
#define bpf_htonl(x) ((__be32)(x))
#define bpf_ntohl(x) (__u32)(x)
#else
#error "Unsupported byte order"
#endif

/* ------------------------------------------------------------------ */
/* Program and map declaration macros (libbpf bpf_helpers.h subset)     */
/* ------------------------------------------------------------------ */

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif

/* linux/pkt_cls.h */
#define TC_ACT_UNSPEC (-1)
/* linux/bpf.h enum bpf_map_type */
#define BPF_MAP_TYPE_RINGBUF 27
/* linux/if_ether.h */
#define ETH_ALEN 6
#define ETH_P_IP 0x0800

/* ------------------------------------------------------------------ */
/* UAPI struct layouts                                                  */
/* ------------------------------------------------------------------ */

struct ethhdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	__be16 h_proto;
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 ihl:4,
	     version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 version:4,
	     ihl:4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
	/* The program never touches IP options through this struct; options
	 * are skipped arithmetically via ihl. */
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 res1:4,
	      doff:4,
	      fin:1,
	      syn:1,
	      rst:1,
	      psh:1,
	      ack:1,
	      urg:1,
	      ece:1,
	      cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff:4,
	      res1:4,
	      cwr:1,
	      ece:1,
	      urg:1,
	      ack:1,
	      psh:1,
	      rst:1,
	      syn:1,
	      fin:1;
#endif
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

/*
 * struct __sk_buff — the TC context. The field prefix below MUST stay
 * layout-identical to the UAPI definition in linux/bpf.h: the verifier maps
 * context accesses by OFFSET. Fields after data_end exist in the UAPI and
 * are intentionally omitted; extend the prefix only in UAPI order.
 */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
};

/* ------------------------------------------------------------------ */
/* Helper declarations                                                  */
/* ------------------------------------------------------------------ */
/*
 * Classic static-pointer style: the helper ID is embedded in the source and
 * the LLVM BPF backend folds calls through the constant-initialized pointer
 * into direct `call <id>` instructions. This is the style cilium/ebpf's own
 * bpf_helper_defs.h uses (that loader does NOT resolve extern-by-name the
 * way libbpf does) and it works identically under libbpf. IDs are stable
 * Linux UAPI (__BPF_FUNC_MAPPER in linux/bpf.h); verify against it when
 * touching this list.
 */

static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;
static long (*bpf_skb_load_bytes)(void *skb, __u32 offset, void *to, __u32 len) = (void *) 26;

#endif /* MIBEE_BPF_STANDALONE_H */
