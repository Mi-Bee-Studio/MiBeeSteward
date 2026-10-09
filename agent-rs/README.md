# mibee-agent-rs

Rust implementation of the MiBee Steward distributed agent (agent v2).
Requirements: GitHub issue #471 (TDD, full replacement of the Go agent,
no hardcoded environment values). Behavior reference: the Go
implementation (the main repo's `cmd/agent` + `internal/*` — this tree
lives at `agent-rs/` inside that repo; the original standalone checkout
sat next to it) — where docs and Go code disagree, the Go code wins.

## Layout

- `crates/mibee-fingerprints` — fingerprint rule classifier (port of
  mibee-fingerprints-go). Corpus is data (CC-BY-SA upstream), loaded from
  a directory; never embedded here.
- `crates/mibee-agent` — the agent binary: wire types, config, center
  client, scan engine.
- `difftest/` — differential test rig against the Go classifier:
  `gen_case_tables.go` (Go-generated case-mapping tables), `gen_battery.py`
  (deterministic battery), `run_difftest.sh`, `go_oracle_main.go` (build
  into mibee-fingerprints-go/tmp/oracle/).
- `crates/mibee-agent/assets/` — synced copies of the main repo's embedded
  OUI table and device_types.yaml; sync, never hand-edit.

## Build / test

    cargo test --workspace
    bash difftest/run_difftest.sh            # byte-identical vs Go oracle

Cross (musl static; zig via `pip install ziglang==0.13.0`):

    ZIGEXE=$(python -c 'import ziglang,os;print(os.path.join(os.path.dirname(ziglang.__file__),"zig.exe"))')
    CARGO_ZIGBUILD_ZIG_COMMAND="$ZIGEXE" cargo zigbuild --release \
      --target aarch64-unknown-linux-musl -p mibee-agent
    # armv7-unknown-linux-musleabihf likewise

NOTE: do NOT let cargo-zigbuild pick its own zig command on this host —
the pyenv `python3.bat` shim resolves to a Python without ziglang.

Version: `-version` reports `MIBEE_AGENT_VERSION` when that env var is set
at BUILD time (the release pipeline stamps the git tag through it), else
the Cargo.toml version.

## Status: DEPLOYED (2026-10-07, agent 0.1.5)

All milestones complete; the Rust agent replaced the Go agent on BOTH rig
nodes and parity gaps closed in 0.1.1 (issue #471 acceptance):

- NEO armv7 (systemd) and R68S arm64 (procd via the
  iStore .run channel) run `mibee-agent-rs/0.1.3`; center fleet
  telemetry, command-driven scans, local cron scans, reports, and corpus
  sync all verified live after the 0.1.1 swap.
- Router-ARP cross-subnet MAC resolution + the `router_arp` passive
  discovery source landed in 0.1.3 (the `routers` config field is no
  longer dead): SNMP GetNext walk primitive (v2c + v3 USM), RFC 4293
  fallback column, 30s single-flight per-(router, credential) cache,
  post-gather MAC fallback wired into the scan path with OUI vendor
  fold. Byte-diff parity against gosnmp walking a REAL net-snmp agent
  (`difftest/walkclient` vs `examples/walk_arp.rs`): v2c 5/5, RFC 4293
  fallback 5/5, v3 authPriv SHA/AES 5/5 — all identical.
- That real-agent differential also exposed and fixed a latent v3 wire
  bug: `msgMaxSize` 65535 was BER-encoded as `FF FF` (signed = -1) and
  net-snmp silently DROPPED every v3 message we ever sent (our own echo
  agent parsed it leniently, so the self-interop suite never saw it).
- 0.1.5 closes the last evidence-channel parity gap: the TLS probe now
  emits a hostname-kind piece when the leaf cert CN is a single DNS
  label (mirror of the Go probe change 7ddd821) — a router signing its
  model into the CN ("R68S") now reaches the corpus's hostname rules on
  Rust-scanned networks too. Verified live 2026-10-07: the R68S router
  row gained `model=R68S` after one scan on 0.1.5.
- 0.1.4 completes agent-side L2 topology: the main repo's wire extension
  (commit 5325bcd — `neighbors` on ReportedHost, center-side rebuild into
  neighbor evidence + RecordNeighbors on the agent-report apply path)
  made the L2 MIB family meaningful, and this agent now carries all five
  probes (Bridge-MIB FDB, Q-BRIDGE FDB + VLAN names, LLDP, CDP, STP)
  emitting the Go probes' exact evidence shapes, plus IF-MIB ifName port
  resolution. They run behind an SNMP gate (phase-2 gather only when the
  host answered the sys* Get or a passive SNMP observation exists) — Go
  walks every host and pays several walk timeouts per non-SNMP host; the
  gate keeps that at zero, verified live: /24 scan 85s on 0.1.4 vs 86s
  on 0.1.3 with zero SNMP devices on the LAN.
- Wire parity verified end-to-end on the rigs: a synthetic neighbors
  POST against the upgraded center produced a device_neighbors edge
  readable via /devices/{id}/neighbors (throwaway agent token, minted +
  revoked).
- SNMPv3 USM scan execution is COMPLETE (was: degrade to community):
  engine-discovery Report, RFC 3414/7860 key localization + digests,
  DES/AES-CFB128 privacy incl. Blumenthal/Reeder key extension, and
  credential resolution from the agent vault by name (center scan
  commands) and id (scheduler tasks). Cross-language interop
  differential: the gosnmp client (the library the Go agent uses) runs
  11/11 level/auth/priv combos green against the Rust echo agent
  (`difftest/run_v3_interop.sh`, `examples/v3_echo_agent.rs`).
- Full robfig/cron-v3 5-field semantics (ranges, lists, steps, names,
  dom/dow OR rule) drive local scan_tasks; per-identity heartbeat specs
  (http/tcp/icmp/snmp rules from the Go handler cascade) ride scan
  reports; the hostapd WiFi STA source (ctrl-socket walk + iw fallback)
  seeds WiFi telemetry onto hosts at their first L3 MAC sighting.
- Identification parity EXCEEDED the Go baseline (per-LAN after one Rust
  scan cycle: lan-62 brand 94.3%/model 74.3%, lan-63 92.5%/45.3%; the
  morning Go baseline was 89.8%/58.0% overall).
- Resources: binaries 4.7MB (armv7) / 4.9MB (arm64) vs ~19.5MB Go; RSS
  7.5MB idle (NEO) / 12MB under scan vs Go 43-63MB — issue #471 targets
  (3-6MB / 15-25MB) met.
- Scan of a /24: 82s vs the Go agent's 142-165s on the same network.
- Classifier remains differential-tested byte-identical (3 seeds).

MIPS musl (issue #471 deployable target) — SOLVED (0.1.2):

- The rustls stack is compiled provider-agnostic (reqwest
  `rustls-tls-webpki-roots-no-provider`, tokio-rustls without a provider
  feature); `tls_provider::ensure_tls_provider()` installs ring on every
  real target and the pure-Rust oxitls provider on MIPS (ring 0.17 has
  no mips backend — it covers x86/x64/arm/aarch64 only).
- `bash difftest/build_mips.sh` builds both `mipsel-unknown-linux-musl`
  (LE) and `mips-unknown-linux-musl` (BE): nightly `-Z build-std`, plus
  the zig shim (`difftest/zigshim.py`) that rewrites the triples
  cargo-zigbuild/cc-rs pass to zig (both the rust triple and
  cargo-zigbuild's `mipsel-linux-musleabi` spelling break zig 0.13's
  bundled-musl header discovery) and injects `-msoft-float` (rust's mips
  musl targets are soft-float; zig links double-float by default).
- Results: 6.8MB static binaries (no PT_INTERP, machine=8), `-version`
  verified under qemu-user (WSL), and the gosnmp client ran the FULL USM
  matrix against the qemu-MIPS echo agent — mipsel 8/8 combos, mips 3/3
  spot checks (authPriv AES/DES + noAuthNoPriv). No MIPS hardware exists
  in the rigs; qemu-user is the execution proof.
- MIPS-specific code note: std has no 64-bit lock-free atomics on
  mips32 — the reporter counters are AtomicU32 (epoch start kept in
  seconds).
