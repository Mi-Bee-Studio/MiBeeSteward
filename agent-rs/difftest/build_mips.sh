#!/usr/bin/env bash
# Build the agent for MIPS musl (mips + mipsel), static, via zig cc.
#
# Three things make this work on a Windows host (see README "MIPS"):
#   1. nightly + `-Z build-std` — the mips musl targets are tier-3, std is
#      built from rust-src on the fly;
#   2. a zig shim that rewrites the triples cargo-zigbuild/cc-rs hand to
#      zig (`mipsel-unknown-linux-musl` and cargo-zigbuild's own
#      `mipsel-linux-musleabi` spelling both break zig 0.13's bundled-musl
#      header discovery) and injects `-msoft-float` (rust's mips musl
#      targets are soft-float; zig links double-float by default);
#   3. ring is NOT in the dep graph for mips — see crates/mibee-agent
#      Cargo.toml's target-conditional provider deps (oxitls on mips).
#
# Usage: bash difftest/build_mips.sh   (from the repo root)
set -eu
cd "$(dirname "$0")/.."

# Locate zig the same way the README does (pyenv python has ziglang).
ZIGEXE="${CARGO_ZIGBUILD_ZIG_COMMAND:-$(python -c 'import ziglang,os;print(os.path.join(os.path.dirname(ziglang.__file__),"zig.exe"))')}"
if [ ! -f "$ZIGEXE" ]; then
  echo "zig not found (CARGO_ZIGBUILD_ZIG_COMMAND override available)" >&2
  exit 1
fi

# Materialize the shim next to this script (idempotent).
SHIM_DIR="$(cygpath -w "$PWD/difftest")\\zigshim-run"
mkdir -p difftest/zigshim-run
python - "$(cygpath -w "$PWD/difftest/zigshim.py")" "$ZIGEXE" "$SHIM_DIR\\zigshim.py" <<'PYEOF'
import sys
src, zig, dst = sys.argv[1:4]
s = open(src, encoding="utf-8").read()
s = s.replace('REPLACE_ME_ZIG_EXE', zig)
open(dst, "w", encoding="utf-8", newline="\n").write(s)
print("shim:", dst)
PYEOF
printf '@echo off\r\npython "%s\\zigshim.py" %%*\r\n' "$SHIM_DIR" > difftest/zigshim-run/zigshim.bat

export CARGO_ZIGBUILD_ZIG_COMMAND="$SHIM_DIR\\zigshim.bat"
for t in mipsel-unknown-linux-musl mips-unknown-linux-musl; do
  echo "== $t =="
  cargo clean -p libsqlite3-sys --target "$t" 2>/dev/null || true
  rm -rf "target/$t/release/build/libsqlite3-sys-"*
  cargo +nightly zigbuild -Z build-std=std,panic_abort --release --target "$t" -p mibee-agent
  ls -la "target/$t/release/mibee-agent" | awk '{print "binary:", $5, "bytes"}'
done
