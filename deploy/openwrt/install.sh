#!/bin/sh
#
# MiBee Steward installer for OpenWrt / iStoreOS routers: form C (center ON
# the router), NO Docker. Runs as root ON the router, from the directory that
# holds the release files (mibee-steward, mibee-steward.init,
# config.example.yaml): typically after extracting the tarball produced by
# `make package-openwrt` on your build host:
#
#   scp bin/mibee-steward-openwrt-arm64-*.tar.gz root@router:/tmp/
#   ssh root@router 'cd /tmp && tar -xzf mibee-steward-openwrt-arm64-*.tar.gz && ./install.sh'
#
# What it does:
#   1. Gates on architecture (ARM/ARM64 OK; MIPS aborts: modernc/libc limit)
#      and smoke-executes the binary to catch arch mismatches early.
#   2. Installs the binary to /usr/bin/mibee-steward and the procd init script
#      to /etc/init.d/mibee-steward.
#   3. FIRST INSTALL ONLY: generates /etc/mibee/config.yaml from
#      config.example.yaml: random jwt_secret, cookie_secure=false (plain
#      HTTP on the LAN), EMPTY initial admin password (the web UI's first-run
#      screen asks you to create one), network.name/cidr derived from
#      `uci get network.lan.*`, absolute DB + upload paths under
#      /etc/mibee/data/ (procd CWD=/ makes the relative defaults land at /;
#      the init script also injects absolute paths via MIBEE_* env).
#      Re-runs (upgrades) keep the existing config untouched.
#   4. Opens net.ipv4.ping_group_range (OpenWrt default `1 0` blocks the
#      unprivileged ICMP ping sockets the probes use) + persists it.
#   5. Enables + starts the service, then hits /api/v1/health.
#
# The SPA is EMBEDDED in the binary: after install, browse to
# http://<router-lan-ip>:<port> from any machine on the LAN. The router itself
# needs no display or frontend runtime.
#
# Usage: ./install.sh [--port N] [--from-ipk]    (default port 8080)
#
# --from-ipk: the .ipk postinst entry (make package-openwrt-ipk). Files are
# already laid down by opkg (/usr/bin/mibee-steward, /etc/init.d/,
# /etc/mibee/config.example.yaml, this script at /usr/lib/mibee/install.sh);
# only the configuration half runs (config generation + ping_group_range +
# enable + start + health check): no file copying.
#
set -eu

BIN_SRC=./mibee-steward
INIT_SRC=./mibee-steward.init
CONF_SRC=./config.example.yaml
BIN_DST=/usr/bin/mibee-steward
CONF_DIR=/etc/mibee
CONF_DST=$CONF_DIR/config.yaml
DATA_DIR=$CONF_DIR/data
SERVICE=mibee-steward
PORT=8080
FROM_IPK=0

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="${2:?--port needs a value}"; shift 2 ;;
        --from-ipk) FROM_IPK=1; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "ERROR: unknown option: $1 (usage: $0 [--port N] [--from-ipk])" >&2; exit 1 ;;
    esac
done

if [ "$FROM_IPK" = 1 ]; then
    CONF_SRC=/etc/mibee/config.example.yaml
fi

[ "$(id -u)" = 0 ] || { echo "ERROR: run as root (ssh root@router)."; exit 1; }

case "$(uname -m)" in
    aarch64|armv8*) echo "-- arch: $(uname -m) (arm64) OK" ;;
    armv7*|armv6*)  echo "-- arch: $(uname -m) (arm) OK" ;;
    mips*)
        echo "ERROR: MIPS is not supported: modernc.org/libc (the pure-Go SQLite"
        echo "       backend) has no working mips port. See docs openwrt.md 'Not covered'."
        exit 1 ;;
    *) echo "-- WARN: untested arch $(uname -m), continuing anyway" ;;
esac

if [ "$FROM_IPK" = 1 ]; then
    [ -f "$BIN_DST" ] || { echo "ERROR: $BIN_DST missing: ipk data incomplete."; exit 1; }
    [ -f "$CONF_SRC" ] || { echo "ERROR: $CONF_SRC missing: ipk data incomplete."; exit 1; }
    # Archives built on Windows/MSYS can carry 0644 on the ELF binary (MSYS
    # only marks PE/shebang files executable: an aarch64 ELF is neither).
    # opkg has already laid the files down; normalize BEFORE the -x gate and
    # the smoke run below, or they fail on a file that is present.
    chmod 755 "$BIN_DST" /etc/init.d/mibee-steward 2>/dev/null || true
    SMOKE_BIN="$BIN_DST"
else
    [ -x "$BIN_SRC" ]  || { echo "ERROR: $BIN_SRC not found: run this inside the extracted tarball dir."; exit 1; }
    [ -f "$INIT_SRC" ] || { echo "ERROR: $INIT_SRC not found: run this inside the extracted tarball dir."; exit 1; }
    [ -f "$CONF_SRC" ] || { echo "ERROR: $CONF_SRC not found: run this inside the extracted tarball dir."; exit 1; }
    SMOKE_BIN="$BIN_SRC"
fi

# A wrong-arch ELF dies with a confusing "not found" from the shell: catch it here.
if ! "$SMOKE_BIN" -version >/dev/null 2>&1; then
    echo "ERROR: $SMOKE_BIN fails to execute (router is $(uname -m); binary built for"
    echo "       another GOARCH?). Rebuild with the matching cross-compile target."
    exit 1
fi

# gen_secret: random alnum using ONLY core busybox applets (head/tr/cut).
# `base64` is NOT guaranteed on router busybox builds: iStoreOS 24.10 on the
# FastRhino R68S ships without it (field-found: install died with
# "base64: not found", the empty jwt_secret landed in config.yaml, and the
# server refused to start). Filter 1KiB of urandom down to [A-Za-z0-9]
# (~250 survivors) and cut 40; retry from 4KiB in the statistically absurd
# short case. Echoes nothing if /dev/urandom is somehow unusable.
gen_secret() {
    _s="$(head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-40)"
    [ "${#_s}" -ge 32 ] || _s="$(head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-40)"
    [ "${#_s}" -ge 32 ] || _s=""
    echo "$_s"
}

# mask_to_prefix 255.255.255.0 -> 24. Same busybox-portability story as
# gen_secret: `ipcalc` is not guaranteed either (the same R68S build lacks
# it), so the cidr derivation needs a pure-ash fallback. Contiguous masks
# only; echoes nothing (and returns 1) on anything else.
mask_to_prefix() {
    _p=0 _zero=0 _rest="$1"
    while [ -n "$_rest" ]; do
        _o="${_rest%%.*}"
        case "$_rest" in *.*) _rest="${_rest#*.}" ;; *) _rest="" ;; esac
        case "$_o" in
            255) [ "$_zero" = 0 ] || return 1; _p=$((_p+8)) ;;
            254) [ "$_zero" = 0 ] || return 1; _p=$((_p+7)); _zero=1 ;;
            252) [ "$_zero" = 0 ] || return 1; _p=$((_p+6)); _zero=1 ;;
            248) [ "$_zero" = 0 ] || return 1; _p=$((_p+5)); _zero=1 ;;
            240) [ "$_zero" = 0 ] || return 1; _p=$((_p+4)); _zero=1 ;;
            224) [ "$_zero" = 0 ] || return 1; _p=$((_p+3)); _zero=1 ;;
            192) [ "$_zero" = 0 ] || return 1; _p=$((_p+2)); _zero=1 ;;
            128) [ "$_zero" = 0 ] || return 1; _p=$((_p+1)); _zero=1 ;;
            0)   _zero=1 ;;
            *)   return 1 ;;
        esac
    done
    echo "$_p"
}

# ip_mask_base 192.168.62.1 255.255.255.0 -> 192.168.62.0 (per-octet AND).
ip_mask_base() {
    _ip="$1" _mask="$2" _out=""
    while [ -n "$_ip" ]; do
        _io="${_ip%%.*}"; case "$_ip" in *.*) _ip="${_ip#*.}" ;; *) _ip="" ;; esac
        _mo="${_mask%%.*}"; case "$_mask" in *.*) _mask="${_mask#*.}" ;; *) _mask="" ;; esac
        _b=$(( _io & _mo ))
        _out="${_out}${_out:+.}$_b"
    done
    echo "$_out"
}

# enable_source KEY: flips "enabled: false" to true inside the YAML block
# "KEY:" of the generated config (block-scoped awk identical to luci-helper.sh
# set_source; busybox-awk safe: match()+sub() only, no gsub extensions).
# Scoped to the block so the many unrelated "enabled:" keys stay untouched.
enable_source() {
    _key="$1"
    awk -v key="$_key" -v val="1" '
        $0 ~ "^[[:space:]]*" key ":[[:space:]]*$" { inblk=1; ind=match($0,/[^ \t]/)-1; print; next }
        inblk {
            n=match($0,/[^ \t]/)-1
            if ($0 !~ /^[[:space:]]*$/ && n<=ind) inblk=0
        }
        inblk && /^[[:space:]]*enabled:/ { sub(/enabled:[[:space:]]*(true|false)/, "enabled: " (val==1 ? "true" : "false")) }
        { print }
    ' "$CONF_DST" > "$CONF_DST.tmp" && mv "$CONF_DST.tmp" "$CONF_DST" \
        || { rm -f "$CONF_DST.tmp"; echo "ERROR: enable_source($1) rewrite failed"; exit 1; }
}

# ─── 1. config (first install generates; upgrades keep) ────────────────────
if [ -f "$CONF_DST" ]; then
    echo "-- config $CONF_DST exists: keeping it (upgrade install)"
    # Self-heal: installs produced before the gen_secret fix (busybox builds
    # without `base64`) carry an EMPTY jwt_secret, and the server refuses to
    # start until it is fixed: the "keep existing config" rule would preserve
    # a config that can never boot. Regenerate the secret instead.
    if grep -qE '^[[:space:]]*jwt_secret:[[:space:]]*""' "$CONF_DST" 2>/dev/null; then
        _fix_secret="$(gen_secret)"
        if [ -n "$_fix_secret" ]; then
            sed -i "s|^\([[:space:]]*jwt_secret:\).*|\1 \"$_fix_secret\"|" "$CONF_DST"
            echo "-- repaired empty jwt_secret in existing config (regenerated)"
        fi
    fi
    # Tier-1 passive discovery (#360): pre-#360 installs generated configs
    # with the router-resident sources off. Keep the operator's config as-is
    # (upgrade rule), just point at the one-click toggle.
    if ! grep -A1 '^[[:space:]]*dhcp_leases:' "$CONF_DST" 2>/dev/null | grep -q 'enabled: true'; then
        echo "-- note: Tier-1 passive discovery (dhcp_leases/conntrack/hostapd) is OFF in this config."
        echo "--       enable under LuCI > Services > MiBee Steward > Settings (one click)"
    fi
else
    # LAN cidr from uci (static lan is the norm on OpenWrt/iStoreOS).
    NET_NAME="lan"
    NET_CIDR=""
    LAN_IP="$(uci -q get network.lan.ipaddr || true)"
    LAN_MASK="$(uci -q get network.lan.netmask || true)"
    NET_BASE="" NET_PREFIX=""
    if [ -n "$LAN_IP" ] && [ -n "$LAN_MASK" ]; then
        if command -v ipcalc >/dev/null 2>&1; then
            # busybox ipcalc -pn prints NET=<base> and PREFIX=<n>
            eval "$(ipcalc -pn "$LAN_IP" "$LAN_MASK" 2>/dev/null || true)"
            NET_BASE="${NET:-}"
            NET_PREFIX="${PREFIX:-}"
        fi
        if [ -z "$NET_BASE" ] || [ -z "$NET_PREFIX" ]; then
            # ipcalc not present (see mask_to_prefix): pure-ash fallback.
            NET_PREFIX="$(mask_to_prefix "$LAN_MASK" || true)"
            NET_BASE="$(ip_mask_base "$LAN_IP" "$LAN_MASK")"
        fi
        if [ -n "$NET_BASE" ] && [ -n "$NET_PREFIX" ] && [ "$NET_PREFIX" -gt 0 ] 2>/dev/null; then
            NET_CIDR="$NET_BASE/$NET_PREFIX"
            OCT3="$(echo "$NET_BASE" | cut -d. -f3)"
            [ -n "$OCT3" ] && NET_NAME="lan-$OCT3"   # project convention: lan-<3rd octet>
        fi
    fi
    [ -n "$NET_CIDR" ] || echo "-- WARN: could not derive LAN cidr from uci: edit network.cidr in $CONF_DST"

    JWT_SECRET="$(gen_secret)"
    [ -n "$JWT_SECRET" ] || { echo "ERROR: cannot generate jwt_secret (/dev/urandom unusable?)"; exit 1; }

    # The admin password is NOT set here: an EMPTY
    # initial_admin_password seeds the admin with no password, and the web UI's
    # first-run screen asks the operator to CREATE one in the browser (the
    # login page detects it via GET /auth/setup-status). Nothing to copy from
    # the installer output, nothing to satisfy a character-class policy before
    # login exists.

    mkdir -p "$CONF_DIR"
    sed \
        -e "s|^\([[:space:]]*port:\) 8080|\1 $PORT|" \
        -e "s|^\([[:space:]]*jwt_secret:\).*|\1 \"$JWT_SECRET\"|" \
        -e "s|^\([[:space:]]*initial_admin_password:\).*|\1 \"\"|" \
        -e "s|^\([[:space:]]*cookie_secure:\) true|\1 false|" \
        -e "s|^\([[:space:]]*name:\) \"default\"|\1 \"$NET_NAME\"|" \
        -e "s|^\([[:space:]]*cidr:\) \"\"|\1 \"$NET_CIDR\"|" \
        -e "s|^\([[:space:]]*path:\) \"./data/mibee.db\"|\1 \"$DATA_DIR/mibee.db\"|" \
        -e "s|^\([[:space:]]*upload_path:\) \"./data/uploads\"|\1 \"$DATA_DIR/uploads\"|" \
        "$CONF_SRC" > "$CONF_DST"
    # Tier-1 passive discovery ON by default (#360): install.sh only runs on
    # OpenWrt/iStoreOS, where the host IS the gateway: the DHCP lease table
    # (authoritative hostname<->MAC<->IP map), conntrack ("who is talking right
    # now") and hostapd (WiFi STA list) are free signals a wired scanner can
    # never see. dns_log stays OFF: it additionally needs dnsmasq query logging
    # (operator UCI change, printed below); the LuCI settings page offers it as
    # a one-click toggle with the note.
    enable_source discovery
    enable_source dhcp_leases
    enable_source conntrack
    enable_source hostapd
    # Guard the generator against itself: a sed script error (e.g. an
    # unterminated s|||: seen in the wild as "sed: unmatched '|'") leaves an
    # EMPTY config.yaml behind, and the "keep existing config" upgrade path
    # would then preserve that empty file forever. Fail loudly instead.
    if [ ! -s "$CONF_DST" ] \
        || ! grep -q '^[[:space:]]*initial_admin_password: ""' "$CONF_DST" \
        || ! grep -q '^[[:space:]]*cookie_secure: false' "$CONF_DST" \
        || ! grep -qE '^[[:space:]]*jwt_secret: "[A-Za-z0-9]{32,}"' "$CONF_DST" \
        || ! grep -A1 '^[[:space:]]*discovery:' "$CONF_DST" | grep -q 'enabled: true' \
        || ! grep -A1 '^[[:space:]]*dhcp_leases:' "$CONF_DST" | grep -q 'enabled: true' \
        || grep -q 'change-me-in-production' "$CONF_DST"; then
        echo "ERROR: generated $CONF_DST failed its sanity check: sed pipeline broken?"
        echo "       (empty file / missing auth keys / short jwt_secret / unreplaced placeholder"
        echo "        / Tier-1 discovery flip missing)"
        rm -f "$CONF_DST"
        exit 1
    fi
    chmod 600 "$CONF_DST"
    echo "-- generated $CONF_DST (network: $NET_NAME $NET_CIDR, db: $DATA_DIR/mibee.db)"
    echo "-- Tier-1 passive discovery ON: dhcp_leases + conntrack + hostapd (router-resident)"
    echo "--   dns_log (DNS query fingerprinting) is available but OFF: needs"
    echo "--   uci set dhcp.@dnsmasq[0].logqueries=1 && uci commit dhcp && /etc/init.d/dnsmasq restart"
    echo "--   then enable it in LuCI (Services > MiBee Steward > Settings) or config.yaml"
    echo "-- cookie_secure forced to false (router form factor = plain HTTP on the LAN;"
    echo "   a Secure cookie would be silently dropped by the browser)"
fi

# ─── 2. ping_group_range (ICMP probes) ─────────────────────────────────────
CUR_RANGE="$(cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo '1 0')"
if [ "$CUR_RANGE" = "0 2147483647" ]; then
    echo "-- ping_group_range already open"
else
    if echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range 2>/dev/null; then
        mkdir -p /etc/sysctl.d
        [ -f /etc/sysctl.d/99-mibee.conf ] || \
            echo "net.ipv4.ping_group_range = 0 2147483647" > /etc/sysctl.d/99-mibee.conf
        echo "-- ping_group_range opened + persisted (/etc/sysctl.d/99-mibee.conf)"
    else
        echo "-- WARN: could not set ping_group_range (ICMP probes will fail with permission denied)"
    fi
fi

# ─── 3. binary + init script + service ─────────────────────────────────────
/etc/init.d/$SERVICE stop >/dev/null 2>&1 || true
if [ "$FROM_IPK" != 1 ]; then
    cp "$BIN_SRC" "$BIN_DST" && chmod 755 "$BIN_DST"
    cp "$INIT_SRC" /etc/init.d/$SERVICE && chmod 755 /etc/init.d/$SERVICE
fi
/etc/init.d/$SERVICE enable
/etc/init.d/$SERVICE start
echo "-- service installed + started (boot-enabled)"

# ─── 4. verify + summary ───────────────────────────────────────────────────
# A single probe after `sleep 2` false-negatives on slower boards (R68S:
# service healthy at t+4s, install warned "health check failed"). A cold
# start's first boot can outrun one shot; retry for up to ~12s instead.
HEALTH_OK=0
if command -v curl >/dev/null 2>&1; then
    _i=0
    while [ "$_i" -lt 12 ]; do
        if curl -sf "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then
            HEALTH_OK=1
            break
        fi
        _i=$((_i+1))
        sleep 1
    done
    if [ "$HEALTH_OK" = 1 ]; then
        echo "-- health check OK (http://127.0.0.1:$PORT/api/v1/health)"
    else
        echo "-- WARN: health check failed: check logs: logread -e $SERVICE | tail -30"
    fi
else
    echo "-- (curl not installed; verify manually: http://127.0.0.1:$PORT/api/v1/health)"
fi

LAN_IP="$(uci -q get network.lan.ipaddr || true)"
[ -n "$LAN_IP" ] || LAN_IP="<router-ip>"
echo ""
echo "================ MiBee Steward installed ================"
echo "  Web UI:      http://$LAN_IP:$PORT   (from any LAN machine's browser)"
if [ -f "$CONF_DST" ] && grep -q '^[[:space:]]*initial_admin_password: ""' "$CONF_DST" 2>/dev/null; then
    echo "  First run:   open the Web UI: it will ask you to CREATE the admin"
    echo "               password in the browser (no temp password, no CLI)."
else
    echo "  Login:       admin / <your existing password from $CONF_DST>"
fi
echo "  Config:      $CONF_DST   (enable router-only discovery sources under"
echo "                scanner.discovery.*: dhcp_leases / conntrack / hostapd / dns_log)"
echo "  Logs:        logread -e $SERVICE"
echo "  Service:     /etc/init.d/$SERVICE {start|stop|restart|enable|disable}"
echo "  Doctor:      $BIN_DST doctor -config $CONF_DST"
if [ "$FROM_IPK" = 1 ]; then
    echo "  Upgrade:     opkg install /tmp/mibee-steward_<new-version>_$([ "$(uname -m)" = aarch64 ] && echo arm64 || echo arm).ipk"
else
    echo "  Upgrade:     re-run ./install.sh from a fresh tarball (config is kept)"
fi
echo "========================================================="
