#!/bin/sh
#
# Assemble a hand-rolled .apk for OpenWrt 24.10+ (apk-tools v2 package format)
# from a prepared staging root — the packaging half of `make package-openwrt-apk`.
#
#   usage: mkapk.sh <staging_root> <version> <goarch> <out.apk>
#
#   staging_root/            ← prepared by the Makefile target
#     usr/bin/mibee-steward
#     etc/init.d/mibee-steward
#     etc/mibee/config.example.yaml
#     usr/lib/mibee/install.sh      (invoked by .post-install with --from-ipk)
#
# iStoreOS/OpenWrt 24.10+ replaced opkg (.ipk) with apk. An apk-tools v2
# package is a single gzip tar: dot-prefixed control members first (.PKGINFO,
# then optional lifecycle scripts — hyphenated names: .pre-install,
# .post-install, .pre-deinstall, .post-deinstall), followed by the payload.
# Install with:  apk add --allow-untrusted /tmp/mibee-steward_<ver>_<arch>.apk
#
# arch = all on purpose (same rationale as the .ipk): the payload is a
# CGO-free static binary, so the arch gate is the .pre-install uname check +
# the post-install `-version` smoke run, not a per-target arch-name match.
#
set -eu

ROOT="${1:?usage: mkapk.sh <staging_root> <version> <goarch> <out.apk>}"
VER="${2:?version required}"
GOARCH_APK="${3:?goarch required (arm64|arm)}"
OUT="${4:?output path required}"

case "$VER" in
    ""|-*|*" "*) echo "ERROR: invalid apk version '$VER'." >&2; exit 1 ;;
esac

case "$GOARCH_APK" in
    arm64) UNAME_OK='aarch64|armv8*' ;;
    arm)   UNAME_OK='armv7*|armv6*' ;;
    *)     echo "ERROR: unsupported GOARCH '$GOARCH_APK' (expected arm64 or arm)." >&2; exit 1 ;;
esac

APK_ARCH=all
SIZE_BYTES="$(du -sk "$ROOT" | awk '{print $1 * 1024}')"

# Control members are written straight into the staging root (dot-prefixed),
# tar'd first, then removed — the root is otherwise payload-only.
cleanup() { rm -f "$ROOT/.PKGINFO" "$ROOT/.pre-install" "$ROOT/.post-install" \
                   "$ROOT/.pre-deinstall" "$ROOT/.post-deinstall"; }
trap cleanup EXIT

# ─── .PKGINFO ──────────────────────────────────────────────────────────────
cat > "$ROOT/.PKGINFO" <<EOF
pkgname = mibee-steward
pkgver = $VER
arch = $APK_ARCH
pkgdesc = Device discovery and monitoring center (CMDB-lite for network/IoT assets) with embedded web UI; CGO-free static binary.
size = $SIZE_BYTES
origin = mibee-steward
maintainer = MiBee Studio <https://github.com/Mi-Bee-Studio/MiBeeSteward>
license = AGPL-3.0-or-later
EOF

# ─── lifecycle scripts (apk v2 names use hyphens, not ipk-style prerm/…) ───
cat > "$ROOT/.pre-install" <<EOF
#!/bin/sh
# Arch gate: refuse cleanly BEFORE apk lays down ~24MB onto a mismatched box.
case "\$(uname -m)" in
    $UNAME_OK) ;;
    *) echo "ERROR: mibee-steward: this apk was built for GOARCH=$GOARCH_APK but this machine is \$(uname -m)." >&2
       echo "       Rebuild with the matching arch: make package-openwrt-apk GOARCH=<arm64|arm>" >&2
       exit 1 ;;
esac
exit 0
EOF

cat > "$ROOT/.post-install" <<'EOF'
#!/bin/sh
# Files are already laid down by apk — configure + start via the same code
# path as the tarball installer (config generation, ping_group_range,
# enable + start, health check). Invoked through `sh` so install.sh needs no
# exec bit (MSYS-built archives can carry 0644; install.sh chmods it back).
# apk passes <pkgname> <pkgver> as arguments — deliberately NOT forwarded.
exec sh /usr/lib/mibee/install.sh --from-ipk
EOF

cat > "$ROOT/.pre-deinstall" <<'EOF'
#!/bin/sh
# Runs before removal AND before an upgrade; .post-install re-enables + restarts.
/etc/init.d/mibee-steward stop    >/dev/null 2>&1 || true
/etc/init.d/mibee-steward disable >/dev/null 2>&1 || true
exit 0
EOF

cat > "$ROOT/.post-deinstall" <<'EOF'
#!/bin/sh
echo "mibee-steward removed; /etc/mibee (config + database) was deliberately kept —"
echo "delete it manually if you really want a full wipe."
exit 0
EOF

chmod 755 "$ROOT/.pre-install" "$ROOT/.post-install" \
          "$ROOT/.pre-deinstall" "$ROOT/.post-deinstall"

# ─── single gzip tar: control members first, then the payload ─────────────
tar -czf "$OUT" -C "$ROOT" --owner=0 --group=0 --numeric-owner \
    .PKGINFO .pre-install .post-install .pre-deinstall .post-deinstall \
    usr etc

echo "→ $OUT  (install with: apk add --allow-untrusted <file>.apk)"
