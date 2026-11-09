#!/bin/sh
# migrate-config.test.sh — fixture scenarios for migrate-config.sh (#727).
#
# Runs anywhere POSIX sh runs (dev box, CI, rig): builds config fixtures in a
# scratch dir, runs the migration, and asserts the outcome — append (no probe
# block), insert (probe block lacking quality), no-op byte-identity when the
# operator already has quality (enabled true AND false), idempotency (second
# run changes nothing), `probe:` with a trailing comment, top-level comments
# inside the probe block, probe as the last block without a trailing newline,
# and the missing-file failure.
#
# usage: sh deploy/openwrt/migrate-config.test.sh   (exit 0 = all pass)
set -u

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TMP=$(mktemp -d 2>/dev/null) || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

fail=0
check() {
    if [ "$2" = "$3" ]; then
        echo "ok   $1"
    else
        echo "FAIL $1"
        echo "     expected: [$2]"
        echo "     got:      [$3]"
        fail=1
    fi
}

# migrate <fixture> <scratch-name>: copies the fixture to scratch, runs one
# migration, prints the exit code.
migrate() {
    cp "$1" "$TMP/$2"
    sh "$DIR/migrate-config.sh" "$TMP/$2" >/dev/null 2>&1
    echo $?
}

# count_top_probe FILE: top-level `probe:` block starters.
count_top_probe() {
    grep -cE '^probe:[[:space:]]*(#.*)?$' "$1" 2>/dev/null || true
}

# quality_enabled FILE: the enabled value inside the probe block ("true",
# "false" or "absent").
quality_enabled() {
    awk '
        /^probe:/ { inprobe = 1; next }
        inprobe && /^[^[:space:]#]/ { inprobe = 0 }
        inprobe && /^[[:space:]]+enabled:/ { sub(/^[[:space:]]+enabled:[[:space:]]*/, ""); print; exit }
    ' "$1" 2>/dev/null || true
}

# ── fixtures ────────────────────────────────────────────────────────────────
# pre08: a v0.7.x-era generated config — no probe block at all.
cat > "$TMP/fx-pre08.yaml" <<'EOF'
server:
  port: 8080
auth:
  jwt_secret: "abcdef0123456789abcdef0123456789"
  initial_admin_password: ""
  cookie_secure: false
network:
  name: "lan"
  cidr: "192.0.2.0/24"
database:
  sqlite:
    path: "/etc/mibee/data/mibee.db"
EOF

# probe-no-quality: example-derived config where someone deleted the quality
# child (probe block holds other children).
cat > "$TMP/fx-probe-noq.yaml" <<'EOF'
server:
  port: 8080
probe:
  max_concurrency: 8
  autogen:
    enabled: false
    services: [http, https]
EOF

# quality-true / quality-false: operator explicitly set the key.
cat > "$TMP/fx-qtrue.yaml" <<'EOF'
probe:
  quality:
    enabled: true
EOF
cat > "$TMP/fx-qfalse.yaml" <<'EOF'
probe:
  quality:
    enabled: false
EOF

# trailing-comment + inter-block comments + probe as the LAST block, no
# trailing newline at EOF.
printf 'server:\n  port: 8080\n# a top-level comment before probe\nprobe:  # local probes\n  max_concurrency: 8\n# another comment inside the probe block' > "$TMP/fx-edge.yaml"

# ── 1. append: no probe block at all ────────────────────────────────────────
rc=$(migrate "$TMP/fx-pre08.yaml" c1.yaml)
check "append: exit 0" "0" "$rc"
check "append: one probe block" "1" "$(count_top_probe "$TMP/c1.yaml")"
check "append: quality enabled" "true" "$(quality_enabled "$TMP/c1.yaml")"
check "append: original content kept" "1" "$(grep -c 'port: 8080' "$TMP/c1.yaml")"

# ── 2. idempotency: rerunning the migrated append must be a no-op ──────────
before=$(md5sum "$TMP/c1.yaml" | cut -d' ' -f1)
out=$(sh "$DIR/migrate-config.sh" "$TMP/c1.yaml" 2>&1)
rc=$?
check "idempotent: exit 0" "0" "$rc"
check "idempotent: byte-identical" "$before" "$(md5sum "$TMP/c1.yaml" | cut -d' ' -f1)"
check "idempotent: says nothing to do" "1" "$(printf '%s' "$out" | grep -c 'nothing to do')"

# ── 3. insert: probe block exists, quality child missing ───────────────────
rc=$(migrate "$TMP/fx-probe-noq.yaml" c3.yaml)
check "insert: exit 0" "0" "$rc"
check "insert: one probe block" "1" "$(count_top_probe "$TMP/c3.yaml")"
check "insert: quality enabled" "true" "$(quality_enabled "$TMP/c3.yaml")"
# quality must be a DIRECT child (2-space) right after probe:, autogen intact.
check "insert: direct child position" "1" "$(grep -A1 -E '^probe:[[:space:]]*(#.*)?$' "$TMP/c3.yaml" | grep -c 'quality')"
awk '/^probe:/{f=1;next} f&&/^[^[:space:]#]/{f=0} f' "$TMP/c3.yaml" > "$TMP/c3-block.yaml"
check "insert: autogen kept" "1" "$(grep -c 'autogen' "$TMP/c3-block.yaml")"

# ── 4. no-op: operator's quality wins (true and false) ─────────────────────
cp "$TMP/fx-qtrue.yaml" "$TMP/c4a.yaml"; cp "$TMP/fx-qfalse.yaml" "$TMP/c4b.yaml"
ha=$(md5sum "$TMP/c4a.yaml" | cut -d' ' -f1); hb=$(md5sum "$TMP/c4b.yaml" | cut -d' ' -f1)
rc=0; sh "$DIR/migrate-config.sh" "$TMP/c4a.yaml" >/dev/null 2>&1 || rc=$?
check "noop true: exit 0" "0" "$rc"
check "noop true: byte-identical" "$ha" "$(md5sum "$TMP/c4a.yaml" | cut -d' ' -f1)"
rc=0; sh "$DIR/migrate-config.sh" "$TMP/c4b.yaml" >/dev/null 2>&1 || rc=$?
check "noop false: exit 0" "0" "$rc"
check "noop false: byte-identical" "$hb" "$(md5sum "$TMP/c4b.yaml" | cut -d' ' -f1)"
check "noop false: stays false" "false" "$(quality_enabled "$TMP/c4b.yaml")"

# ── 5. edges: trailing comment / inter-block comments / EOF without newline ─
rc=$(migrate "$TMP/fx-edge.yaml" c5.yaml)
check "edge: exit 0" "0" "$rc"
check "edge: one probe block" "1" "$(count_top_probe "$TMP/c5.yaml")"
check "edge: quality enabled" "true" "$(quality_enabled "$TMP/c5.yaml")"
check "edge: max_concurrency kept" "1" "$(grep -c 'max_concurrency: 8' "$TMP/c5.yaml")"

# ── 6. failure modes ────────────────────────────────────────────────────────
nz() { # nz <rc>: "1" when the exit code was non-zero (no POSIX ternary)
    [ "$1" -gt 0 ] && echo 1 || echo 0
}
rc=0; sh "$DIR/migrate-config.sh" "$TMP/does-not-exist.yaml" >/dev/null 2>&1 || rc=$?
check "missing file: nonzero exit" "1" "$(nz "$rc")"
rc=0; sh "$DIR/migrate-config.sh" >/dev/null 2>&1 || rc=$?
check "no argument: nonzero exit" "1" "$(nz "$rc")"

# ── result ──────────────────────────────────────────────────────────────────
if [ "$fail" = 0 ]; then
    echo "-> migrate-config.test.sh: all pass"
fi
exit $fail
