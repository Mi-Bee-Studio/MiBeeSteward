#!/bin/sh
#
# Assemble a hand-rolled .ipk for opkg (OpenWrt / iStoreOS) from a prepared
# staging root — the packaging half of `make package-openwrt-ipk` (center) and
# `make package-openwrt-agent-ipk` (agent).
#
#   usage: mkipk.sh <staging_root> <version> <goarch> <out.ipk> [kind]
#
#   staging_root/            ← prepared by the Makefile target
#     usr/bin/mibee-steward  (kind=center; usr/bin/mibee-agent for kind=agent)
#     etc/init.d/mibee-steward
#     etc/mibee/config.example.yaml  (agent.example.yaml for kind=agent)
#     usr/lib/mibee/install.sh       (agent-install.sh for kind=agent)
#
#   kind: "center" (default) or "agent" — selects the package name,
#   description and lifecycle wiring (which init script, which installer).
#
# FORMAT NOTE — modern OpenWrt (22.03+) .ipk files are NOT Debian-style ar
# archives: they are gzip( tar(./debian-binary, ./data.tar.gz, ./control.tar.gz) ),
# in that member order, GNU tar format, numeric uid/gid 0. This was verified
# byte-level against official 23.05 feed packages — and a plain-ar .ipk was
# field-rejected on iStoreOS with `pkg_init_from_file: Malformed package file`
# (opkg there does not read the legacy ar container). No OpenWrt SDK is needed
# anyway: the payload is CGO-free/static.
#
# The package architecture is "all" on purpose: OpenWrt's per-target arch
# names (aarch64_generic, aarch64_cortex-a53, arm_cortex-a7_neon-vfpv4, …)
# form a matrix a single static binary doesn't need; the real arch gate is
# the preinst uname check plus the postinst `-version` smoke run. Exact arch
# names (and feed publishing/signing) remain the buildroot follow-up — see
# docs openwrt.md "Not covered here".
#
# Lifecycle scripts:
#   preinst   arch gate (uname must match the GOARCH this ipk was built for)
#   postinst  exec sh /usr/lib/mibee/install.sh --from-ipk  (config generation
#             + ping_group_range + enable + start + health check)
#   prerm     stop + disable (also runs before an upgrade; postinst re-enables)
#   postrm    note that /etc/mibee (config + DB) is deliberately kept
#
set -eu

ROOT="${1:?usage: mkipk.sh <staging_root> <version> <goarch> <out.ipk> [center|agent]}"
VER="${2:?version required}"
GOARCH_IPK="${3:?goarch required (arm64|arm)}"
OUT="${4:?output path required}"
KIND="${5:-center}"

case "$KIND" in
    center) PKG=mibee-steward
            DESC="Device discovery and monitoring center (CMDB-lite for network/IoT assets) with embedded web UI; CGO-free static binary."
            INSTALLER=install.sh ;;
    agent)  PKG=mibee-agent
            DESC="MiBee Steward distributed discovery agent — scans the LAN it sits on and reports to a remote center; CGO-free static binary."
            INSTALLER=agent-install.sh ;;
    *) echo "ERROR: unknown kind '$KIND' (expected center or agent)." >&2; exit 1 ;;
esac

case "$VER" in
    ""|-*|*" "*) echo "ERROR: invalid ipk version '$VER'." >&2; exit 1 ;;
esac

case "$GOARCH_IPK" in
    arm64) UNAME_OK='aarch64|armv8*' ;;
    arm)   UNAME_OK='armv7*|armv6*' ;;
    *)     echo "ERROR: unsupported GOARCH '$GOARCH_IPK' (expected arm64 or arm)." >&2; exit 1 ;;
esac

# The binary is static (CGO_ENABLED=0) — arch-independent from opkg's point of
# view; the uname + smoke-run gates above do the real checking.
OPKG_ARCH=all

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CTRL="$TMP/control"
INNER="$TMP/inner"
mkdir -p "$CTRL" "$INNER"

INSTALLED_SIZE="$(du -sk "$ROOT" | cut -f1)"

# ─── control ───────────────────────────────────────────────────────────────
cat > "$CTRL/control" <<EOF
Package: $PKG
Version: $VER
Architecture: $OPKG_ARCH
Maintainer: MiBee Studio <https://github.com/Mi-Bee-Studio/MiBeeSteward>
Section: net
Installed-Size: $INSTALLED_SIZE
Description: $DESC
EOF

# ─── lifecycle scripts ─────────────────────────────────────────────────────
cat > "$CTRL/preinst" <<EOF
#!/bin/sh
# Arch gate: refuse cleanly BEFORE opkg lays down ~24MB onto a mismatched box.
case "\$(uname -m)" in
    $UNAME_OK) ;;
    *) echo "ERROR: $PKG: this ipk was built for GOARCH=$GOARCH_IPK but this machine is \$(uname -m)." >&2
       echo "       Rebuild with the matching arch: make package-openwrt${KIND:+-$KIND}-ipk GOARCH=<arm64|arm>" >&2
       exit 1 ;;
esac
exit 0
EOF

cat > "$CTRL/postinst" <<EOF
#!/bin/sh
# Files are already laid down by opkg — configure + start via the same code
# path as the tarball installer. Invoked through \`sh\` so the installer needs
# no exec bit (MSYS-built archives can carry 0644; it chmods itself back).
exec sh /usr/lib/mibee/$INSTALLER --from-ipk
EOF

cat > "$CTRL/prerm" <<'EOF'
#!/bin/sh
# Runs before removal AND before an upgrade; postinst re-enables + restarts.
/etc/init.d/SERVICE stop    >/dev/null 2>&1 || true
/etc/init.d/SERVICE disable >/dev/null 2>&1 || true
exit 0
EOF
sed -i "s/SERVICE/$PKG/g" "$CTRL/prerm"

cat > "$CTRL/postrm" <<EOF
#!/bin/sh
echo "$PKG removed; /etc/mibee (config + database) was deliberately kept —"
echo "delete it manually if you really want a full wipe."
exit 0
EOF

chmod 644 "$CTRL/control"
chmod 755 "$CTRL/preinst" "$CTRL/postinst" "$CTRL/prerm" "$CTRL/postrm"

# ─── members (./-prefixed paths, matching official feed ipks) ─────────────
echo "2.0" > "$INNER/debian-binary"
tar -czf "$INNER/data.tar.gz"    -C "$ROOT" --owner=0 --group=0 --numeric-owner .
tar -czf "$INNER/control.tar.gz" -C "$CTRL" --owner=0 --group=0 --numeric-owner \
    ./control ./preinst ./postinst ./prerm ./postrm

# ─── outer container: gzip( tar(./debian-binary ./data.tar.gz ./control.tar.gz) ) ──
# Member order matches official feed ipks (data before control). GNU tar
# default format = "POSIX tar archive (GNU)" as file(1) reports on feed pkgs.
tar -cf "$TMP/ipk.tar" -C "$INNER" --owner=0 --group=0 --numeric-owner \
    ./debian-binary ./data.tar.gz ./control.tar.gz
gzip -n -9 -c "$TMP/ipk.tar" > "$OUT"

echo "→ $OUT  (install with: opkg install <file>.ipk)"
