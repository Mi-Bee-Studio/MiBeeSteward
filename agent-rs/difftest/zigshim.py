"""zig cc shim for the MIPS musl builds (invoked via difftest/build_mips.sh).

Why this exists (zig 0.13 + cargo-zigbuild 0.23 on Windows):
  - cc-rs and cargo-zigbuild hand zig the Rust triple / its own
    `mipsel-linux-musleabi` spelling; under both spellings zig fails to
    discover its bundled musl headers (stdio.h not found) or rejects the
    target outright. `mipsel-linux-musl` is the spelling that works.
  - rustc's mips/mipsel musl targets are soft-float; zig links
    double-float by default and lld aborts with "floating point ABI
    '-msoft-float' is incompatible with target floating point ABI
    '-mdouble-float'". `-msoft-float` is injected for every mips
    invocation (compile and link) so the whole build is soft-float.

Everything else (including `zig version`) passes through untouched.
"""

import subprocess
import sys

ZIG = r"REPLACE_ME_ZIG_EXE"

MAP = {
    # rust triples (from cc-rs) ...
    "mipsel-unknown-linux-musl": "mipsel-linux-musl",
    "mips-unknown-linux-musl": "mips-linux-musl",
    # ... and cargo-zigbuild's own mapping (`-target mipsel-linux-musleabi`),
    # a spelling under which zig 0.13 misses its bundled musl headers.
    "mipsel-linux-musleabi": "mipsel-linux-musl",
    "mips-linux-musleabi": "mips-linux-musl",
}


def main() -> int:
    argv = sys.argv[1:]
    out = []
    mips = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--target="):
            v = MAP.get(a.split("=", 1)[1], a.split("=", 1)[1])
            mips = mips or v.startswith("mips")
            out.append("--target=" + v)
        elif a in ("-target", "--target") and i + 1 < len(argv):
            v = MAP.get(argv[i + 1], argv[i + 1])
            mips = mips or v.startswith("mips")
            out.append(a)
            out.append(v)
            i += 1
        else:
            out.append(a)
        i += 1
    if mips:
        out += ["-msoft-float"]
    return subprocess.call([ZIG] + out)


if __name__ == "__main__":
    sys.exit(main())
