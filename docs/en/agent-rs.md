# The Distributed Agent: Rust (`agent-rs`) vs the Retired Go Agent

> **Status (2026-10-09)**: the Rust agent (`agent-rs/`, cargo workspace) is the **only** distributed agent. The former Go agent (`cmd/agent`) has been **retired and removed** from the repository — its final release was v0.6.0-95; both field rigs had already been running the Rust agent exclusively since 2026-10-06. This page is the complete engineering comparison that backed that decision, with every number pinned to its measurement source.

## Why a rewrite at all

The Go agent worked, but on the edge hardware this product actually targets (ARMv7 SBCs, 256 MB–1 GB RAM routers, flash storage) it carried costs the team could not remove:

- **Memory floor**: a Go runtime + the eager fingerprint corpus kept the agent's resident set in the 40–110 MB band depending on corpus compilation strategy — an order of magnitude above what an ARMv7 board comfortably donates to one daemon.
- **Garbage-collector tails**: scan workers + GC cycles produced RSS oscillation (38–63 MB swings) that made capacity planning on small boxes guesswork.
- **Distribution**: the Go agent was never shipped as a release artifact with parity coverage; builds were ad-hoc per deployment.

GitHub issue **#471** framed the replacement as strict TDD with a hard acceptance gate: **byte-exact classifier parity** against the Go implementation over the full rule corpus, plus wire-protocol compatibility with the existing center. No "rewrite and hope" — every milestone landed behind a differential test.

## Measured comparison

### Method

- **Go baselines**: recorded during the Go agent's production tenure on the same hardware (NanoPi NEO, ARMv7, 512 MB, systemd; the center's `lan-63` network). The memory band is from the 2-day/96-round observer (2026-10-04 → 10-06); scan durations from the same ledger. The eager→lazy corpus-compilation change (fingerprint library v0.1.1) benefited the **Go** agent first; the numbers below are post-optimization Go.
- **Rust numbers**: live production measurements of `mibee-agent-rs/0.1.5` on the same board (2026-10-09), plus fresh builds of both agents from the same commit for binary-size parity.
- Both agents: `-s -w`/release builds, static (no runtime deps), identical scan targets and cadence.

### Binary size

| | Go agent | Rust agent | Ratio |
|---|---|---|---|
| linux/armv7 (deployed arch) | 19,988,640 B | 4,795,716 B | **4.2×** |
| linux/arm64 | 19,464,352 B | ~4.8 MB | ~4.1× |

### Memory (same board, same network, production traffic)

| | Go agent | Rust agent | Ratio |
|---|---|---|---|
| RSS band (2-day observer, 96 rounds) | 38.5 – 62.8 MB | 10.9 – 12.4 MB | — |
| Median RSS | 54.1 MB | 11.9 MB | **4.5×** |
| Live sample 2026-10-09 (2d08h uptime) | — | 12.6 MiB RSS / 11.8 MiB (systemd MemoryCurrent) | — |
| Pre-optimization steady state (eager corpus) | ~110 MB | — | — |

The Rust agent's band is not just lower but **flat**: no GC sawtooth, which is what makes small-board capacity planning deterministic.

### Scan performance (`/24`, active scan, same targets)

| | Go agent | Rust agent |
|---|---|---|
| Duration band | 142 – 165 s | 84.8 – 88.6 s (6 fresh samples, alive=45) |
| Throughput vs Go | 1× | **~1.7×** |

The gain comes mainly from the Rust engine's probe scheduler and the **SNMP gate**: L2/MIB probes run only for hosts that proved they speak SNMP (phase-1 evidence), where the Go engine paid several walk timeouts per non-SNMP host. Verified live: adding the five L2 probes (0.1.4) kept the /24 at 85 s vs 86 s before them.

### Local database footprint

| | Go agent | Rust agent |
|---|---|---|
| `agent.db` steady state | 40 – 47 MB (retention sweep + VACUUM) | 2.58 MB (same retention policy) |

Honesty note: the two agents do not write identical row volumes into their local shadow tables, so this row is indicative rather than like-for-like. The direction is unambiguous though — under the Go agent the file crept toward the flash-unfriendly tens of MB even with its sweep; the Rust agent holds single-digit MB.

### Test & verification depth

| | Go agent | Rust agent |
|---|---|---|
| Unit/integration tests | 105 test functions (`cmd/agent` + `internal/agent`) | 172 tests (workspace, `cargo test`) |
| Classifier parity | reference implementation | **byte-exact difftest** vs the Go classifier over the full corpus (~2,600 rules), double-seed, in-repo oracle (`agent-rs/difftest/`) |
| SNMP wire verification | library trust (gosnmp) | **differential against real net-snmp**: v2c walk 5/5, RFC 4293 fallback 5/5, v3 authPriv (SHA/AES) 5/5 — byte-identical; cross-language interop vs gosnmp 11/11 combos |

The differential testing paid for itself immediately: it exposed a latent BER bug in our own v3 encoder (`msgMaxSize 65535` encoded as `FF FF` = signed −1; real agents silently dropped **every** v3 message we ever sent — the lenient in-house echo server used for self-testing could never see it). Fixed with a regression test; this class of bug is exactly why the acceptance gate was byte-level.

### Code size (the honest cost)

| | Go agent | Rust agent |
|---|---|---|
| Lines of code | 5,152 (Go, leveraging gosnmp/yaml.v3/Go crypto) | 15,937 (Rust, self-contained: own BER, SNMPv3 USM + key localization, AES-GCM vault, cron parser) |

The 3× code growth is the deliberate price of the two requirements that motivated the rewrite: no runtime memory surprises, and no dependency on libraries whose allocation behavior we cannot control. Where the Go agent delegated wire formats to libraries, the Rust agent owns them — and owns their differential tests.

## Feature parity (final state, 0.1.5)

| Capability | Go agent | Rust agent | Notes |
|---|---|---|---|
| Six-endpoint center protocol (report/poll/commands/fingerprints/…) | ✔ | ✔ | contract tests against the same wire types |
| Classifier (fingerprint corpus) | reference | ✔ byte-exact | full-corpus difftest, corpus rev shared fleet-wide (`86e1ff8a` at retirement) |
| SNMPv1/v2c + v3 USM (authPriv, SHA/AES, key localization) | ✔ (via gosnmp) | ✔ (own implementation) | differential-tested, see above |
| Credential vault (AES-256-GCM, secrets never leave the box) | ✔ | ✔ | blob format documented for migration |
| Fingerprint corpus sync (fpsync, rev-negotiated, validated swap) | ✔ | ✔ | same center endpoint |
| Local cron scan tasks (robfig 5-field semantics) | ✔ | ✔ | ranges/lists/steps/dom-dow OR |
| Router ARP walk (legacy + RFC 4293, single-flight cache) | ✔ | ✔ | cross-subnet MAC resolution |
| L2 topology probes (Bridge/Q-BRIDGE/LLDP/CDP/STP) | ✔ | ✔ | behind the SNMP gate (Go paid timeouts per non-SNMP host; Rust does not) |
| `neighbors` wire array → center `device_neighbors` | ✔ | ✔ | landed both sides in the same release train |
| Hostname evidence channels (NBNS, TLS cert CN → hostname rules) | ✔ | ✔ | 0.1.4/0.1.5 |
| hostapd/iw WiFi station telemetry | ✔ | ✔ | live rig validation pending an AP-equipped rig |
| Heartbeat probe specs from report | ✔ | ✔ | |
| Retention sweep + VACUUM | ✔ | ✔ | |
| Config (`agent.yaml` keys + `MIBEE_` env) | ✔ | ✔ | same shape — an existing agent.yaml works unchanged |

## Field record

- **2026-10-06**: both rig agents (NanoPi NEO armv7 via systemd, FastRhino R68S arm64 via the iStoreOS web package channel) switched to the Rust agent. From that moment the rigs' identification pipeline has been Rust-only.
- **0.1.0 → 0.1.5**, five production upgrades across the two rigs: zero failed upgrades, zero service restarts (`NRestarts=0` across the whole window), zero missed scan cadences. The randomized-MAC guard, multi-homed stability fix, and TLS-CN hostname channel were all shipped and field-verified in this window.
- The Go agent's last production duty was 2026-10-06 01:27 UTC (NEO). It was removed from the repository on 2026-10-09.

## Retirement notes for operators

- **Install/upgrade paths**: see [Distributed Deployment](distributed.md). The Go agent's OpenWrt `.ipk`/`.apk`/tarball package forms were removed together with `cmd/agent`; the Rust agent currently ships as static musl binaries (`make build-agent-rs`, aarch64 + armv7) with the router install documented per form. Native Rust `.ipk`/`.apk` packaging is a tracked follow-up.
- **Config**: an existing `agent.yaml` works with the Rust agent unchanged (same keys; unknown keys are ignored with a logged warning).
- **Local data**: the Rust agent's `agent.db` is its own schema (v1). A Go-agent `agent.db` is **not** carried over — it held only a device shadow and scan history; the center's inventory is the source of record and repopulates from the first scan.
- **Version string**: the Rust agent reports `mibee-agent-rs/x.y.z` in the center's fleet view; the center accepts both it and the legacy Go format during a mixed-fleet transition window.

## Release & verification gates

- **CI**: the cargo workspace has its own test job (`agent-rs`) on every PR — the full suite plus the full-corpus load, whose rule-count assertion is a floor (the corpus only grows). Until 2026-10-09 this suite ran only on dev machines; the day the job was added it caught a corpus-count pin that had silently broken on a corpus batch.
- **Release**: a `v*` tag builds static musl binaries for amd64, arm64 and armv7, version-stamped from the tag (`MIBEE_AGENT_VERSION` at build time; ordinary builds report the Cargo.toml version). They attach to the GitHub Release as `mibee-agent-linux-amd64` / `-arm64` / `-armv7`, and the pipeline executes the amd64 binary on the runner to verify the stamp.
- **Measured coverage**: 74.3% lines / 74.6% functions across both crates (`cargo llvm-cov`, 2026-10-09, 19,244 instrumented lines). The raw number understates the verification strength: the parity-critical classifier and SNMP layers are gated by the full-corpus byte-diff and the real net-snmp differentials above, which line coverage cannot see into. A coverage ratchet for the Rust side is a candidate follow-up, not a current gate.

## Known gaps / follow-ups

- **MIPS**: the Rust agent builds for `mipsel` (used by the difftest oracles under QEMU) but MIPS hardware remains unvalidated; MIPS is unsupported by the center regardless (modernc/libc).
- **hostapd live validation**: the WiFi STA source parses real `hostapd_cli`/`iw` captures in tests; a live AP rig is still wanted.
- **Rust agent router packages** (`.ipk`/`.apk` + LuCI integration): the Go packaging scaffolding was retired rather than half-converted; the tarball + init-script path is the documented install until the native packages land.
