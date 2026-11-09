#!/bin/sh
# migrate-config.sh — upgrade-time ADDITIVE config migrations for kept configs
# (#727). install.sh's upgrade rule is "existing config is kept" — correct for
# operator choices, but it also means a config generated before a feature's
# config block existed never gains that block, and the server treats the
# missing key as OFF forever. First field case (#608): a pre-v0.8.0 config
# kept across upgrades has no probe.quality key, so the egress-quality matrix
# never seeds — nothing on the UI says why. This script re-adds the MISSING
# feature-default blocks so a kept config reaches parity with a fresh
# install's generated one (config.example.yaml).
#
# House rules for every migration step here:
#   - ADDITIVE only: create a missing default block; never rewrite or remove
#     anything the operator has. Any explicitly-present key wins as-is
#     (quality.enabled: false stays false — that is a choice, not an absence).
#   - Idempotent: the ipk/tar install path re-runs on same-version reinstalls
#     (the standard verification method) — a second run must be a no-op.
#   - busybox-awk safe: POSIX classes, match/sub-level constructs only (the
#     enable_source precedent in install.sh). Atomic write (tmp + mv); a
#     failed rewrite leaves the original untouched and exits non-zero so
#     install.sh (set -eu) aborts loudly instead of booting a half-migrated
#     config.
#   - Testable: scenarios live in migrate-config.test.sh (run by
#     `make check-openwrt`).
#
# Future config-default features: append a new guarded step below following
# the probe.quality template.
#
# usage: sh migrate-config.sh /etc/mibee/config.yaml     (exit 0 = ok/no-op)
set -eu

CONF="${1:-}"
[ -n "$CONF" ] || { echo "usage: sh migrate-config.sh <config.yaml>" >&2; exit 1; }
[ -f "$CONF" ] || { echo "migrate-config: $CONF not found" >&2; exit 1; }

applied=0

# probe_quality_state FILE: prints two 0/1 digits "<probe><quality>" — whether
# a top-level `probe:` block exists, and whether a `quality:` key sits inside
# it. The block ends at the next top-level key (column 0, non-comment);
# comment lines never end a block. Top-level comment blocks between keys are
# part of neither.
probe_quality_state() {
    awk '
        /^probe:[[:space:]]*(#.*)?$/ { inprobe = 1; hasprobe = 1; next }
        inprobe && /^[^[:space:]#]/ { inprobe = 0 }
        inprobe && /^[[:space:]]+quality:[[:space:]]*(#.*)?$/ { hasquality = 1 }
        END { printf "%d%d\n", hasprobe + 0, hasquality + 0 }
    ' "$1"
}

# ── probe.quality (#608, default-on since v0.8.0) ───────────────────────────
# Only the two-line default block is written; every knob (window, thresholds,
# target groups) has a built-in default in internal/config/probe_config.go,
# which also seeds DefaultQualityGroups when the groups map is empty. Minimal
# block = maximal future compatibility.
state=$(probe_quality_state "$CONF")
case "$state" in
10)
    # probe: block exists without a quality: child — insert quality as its
    # first child (child order is irrelevant to YAML; first keeps it visible).
    awk '
        /^probe:[[:space:]]*(#.*)?$/ && !done {
            print
            print "  quality:"
            print "    enabled: true"
            done = 1
            next
        }
        { print }
    ' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF" \
        || { rm -f "$CONF.tmp"; echo "migrate-config: probe.quality insert FAILED — config left unchanged" >&2; exit 1; }
    echo "-- migration: inserted probe.quality.enabled=true under the existing probe: block"
    echo "    (egress-quality matrix #608, shipped default-on since v0.8.0: a kept pre-0.8"
    echo "     config has no such key and the matrix would stay OFF forever; set"
    echo "     enabled: false to opt out)"
    applied=$((applied + 1))
    ;;
00)
    # No probe block at all — append one (a missing trailing newline is fine:
    # the leading \n terminates whatever the last line was).
    printf '\n# Added by migrate-config.sh: egress-quality matrix (#608),\n# default-on for fresh installs since v0.8.0 (disable with enabled: false).\nprobe:\n  quality:\n    enabled: true\n' >> "$CONF"
    echo "-- migration: appended probe block with quality.enabled=true (egress-quality matrix #608)"
    applied=$((applied + 1))
    ;;
esac

# Post-write verification: whatever we did, the quality key must now exist
# inside the probe block. A silent no-op migration would recreate #727.
if [ "$applied" -gt 0 ]; then
    state=$(probe_quality_state "$CONF")
    case "$state" in
    *1) : ;;
    *)
        echo "migrate-config: verification FAILED (probe.quality still absent after migration)" >&2
        echo "  inspect $CONF by hand before starting the service" >&2
        exit 1
        ;;
    esac
    echo "-- migrations: $applied applied (idempotent: re-running is a no-op)"
else
    echo "-- migrations: nothing to do (config up to date)"
fi
