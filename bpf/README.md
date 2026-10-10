# bpf/, eBPF passive service detection (TCX ingress)

This directory holds the eBPF program that implements the **passive observer**
half of scannerv2's Probe layer. It is built and linked **only** when the
binary is compiled with the `WITH_EBPF` build tag; the default build uses a
no-op stub (`internal/service/scannerv2/ebpf/observer_stub.go`) and has zero
kernel/toolchain dependencies.

## What it does

`tc_ingress.c` attaches to the TCX ingress hook on network interfaces and
inspects incoming packets for known protocol signatures:

| Signature | Evidence kind | Classified as |
|---|---|---|
| TCP payload `SSH-...` | `banner` | ssh |
| TCP payload `RTSP/1...` | `rtsp_banner` | rtsp |
| TCP payload `HTTP/1...` | `banner` | http |
| UDP/3702 ↔ 239.255.255.250 | `wsdiscovery` | onvif |

Matches are emitted to a ring buffer (`events` map) and consumed by the Go
loader, which translates them into `scannerv2.Evidence` with
`Source: "passive:ebpf:tc"` and `Confidence: 0.6`. The classifier layer fuses
this corroborating signal with active-probe evidence.

**The program never modifies or drops packets**, it is pure observation
(`TC_ACT_UNSPEC`). On a bridge, attach the physical ports — bridged frames do
not traverse the bridge device's own TC hook.

## Why passive vs active

ONVIF/WS-Discovery is the cleanest passive target because cameras announce
themselves on a fixed multicast group (239.255.255.250:3702). TCP protocols
(SSH/RTSP/HTTP) are more reliably detected by active probing; the eBPF
magic-byte matching is a *corroborating* signal, not a replacement, hence the
lower confidence.

## Runtime requirements (WITH_EBPF build only)

- **Kernel**: Linux ≥ 6.6 (the loader attaches via TCX — the only TC attach
  path cilium/ebpf v0.22 ships). BTF is **optional**: the program is CO-RE
  free (see below), so it loads on BTF-less kernels too.
- **Privileges**: root, or ambient `CAP_BPF` + `CAP_NET_ADMIN`.
- **Config**: `scanner.ebpf.enabled: true`; empty `interfaces` attaches to
  every non-loopback, up interface.

When requirements are not met the observer degrades gracefully — a lifecycle
state machine (`active`/`degraded`/`unsupported`/`failed`) with actionable
reasons, surfaced in logs and by `mibee-steward doctor`. It never crashes the
server nor blocks active scanning (#493).

## Building

```bash
# Default build, no eBPF (stub):
make build

# Build with eBPF support (requires ONLY clang >= 14, any host OS):
go generate -tags WITH_EBPF ./internal/service/scannerv2/ebpf/
make build-with-ebpf
```

`go generate` compiles `tc_ingress.c` via bpf2go and generates the Go
bindings (gitignored, lowercase `tcingress_*` — the tag is required because
the generate directive lives in a tagged file). `build-with-ebpf` builds the
server with `-tags WITH_EBPF`; the object is embedded into the binary.

## Portability: CO-RE free by construction

`bpf_standalone.h` is a self-contained support header (UAPI types, byte-order
macros, map declaration macros, and the helpers in cilium/ebpf's
static-pointer style with literal IDs). The program uses ONLY stable UAPI
types (`ethhdr`/`iphdr`/`tcphdr`/`udphdr`/`__sk_buff` virtual fields), so:

- **Build**: needs clang only — no bpftool, no `/sys/kernel/btf/vmlinux`, no
  libbpf headers, no Linux headers. Works on any host OS.
- **Load**: no CO-RE relocations in the object (verify with
  `llvm-objdump -r tc_ingress.o` — the only `.text` relocation is the `events`
  map), so kernels without BTF can load it.

Do NOT introduce accesses to kernel-internal types in these programs; that
would silently reintroduce the BTF/CO-RE dependency. Keep verifier bounds
checks complete: every packet field read must be covered by a preceding
bounds check spanning the FULL struct — the TCP header check guards the
`doff` bitfield container at offset 12, so an 8-byte window is not enough
(found on the first-ever live load of this program, see #493/#494).

## Iterating on the C program

```bash
cd bpf && make tc_ingress.o
```

Requires `clang` only. To inspect generated code:
`llvm-objdump -d -S tc_ingress.o` (source interleaving comes from the BTF
line info that `-g` emits).
