# bpf/ — eBPF passive service detection (TC ingress)

This directory holds the eBPF program that implements the **passive observer**
half of scannerv2's Probe layer. It is built and linked **only** when the
binary is compiled with the `WITH_EBPF` build tag; the default build uses a
no-op stub (`internal/service/scannerv2/ebpf/observer_stub.go`) and has zero
kernel/toolchain dependencies.

## What it does

`tc_ingress.c` attaches to the TC (Traffic Control) ingress hook on network
interfaces and inspects incoming packets for known protocol signatures:

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

**The program never modifies or drops packets** — it is pure observation
(`TC_ACT_UNSPEC`).

## Why passive vs active

Research conclusion (see plan): ONVIF/WS-Discovery is the cleanest passive
target because cameras announce themselves on a fixed multicast group
(239.255.255.250:3702). TCP protocols (SSH/RTSP/HTTP) are more reliably
detected by active probing; the eBPF magic-byte matching is a *corroborating*
signal, not a replacement — hence the lower confidence.

## Runtime requirements (WITH_EBPF build only)

- **Kernel**: Linux ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`).
- **Privileges**: `CAP_BPF` + `CAP_NET_ADMIN` (or run as root).
- **Config**: `scanner.ebpf.enabled: true` + `scanner.ebpf.interfaces: [eth0]`
  (empty → attaches to all non-loopback interfaces).

When requirements aren't met, the observer logs a warning and degrades
gracefully to active-only probing.

## Building

```bash
# Default build — no eBPF (stub):
make build

# Build with eBPF support (requires clang/llvm/bpftool + kernel BTF):
make build-with-ebpf
```

`build-with-ebpf` compiles `tc_ingress.c` to a BPF object, generates the Go
bindings via `cilium/ebpf`'s bpf2go, then builds the server with
`-tags WITH_EBPF`. The object is embedded into the binary.

## Iterating on the C program

```bash
cd bpf && make vmlinux.h && make tc_ingress.o
```

This requires `clang`, `llc`, and `bpftool`. The generated `vmlinux.h` is
machine-specific (from the running kernel's BTF) and is gitignored.
