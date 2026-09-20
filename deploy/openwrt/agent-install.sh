#!/bin/sh
#
# MiBee Steward AGENT installer for OpenWrt / iStoreOS routers — form B
# (agent ON the router, reporting to a remote center). Runs as root ON the
# router, from the directory that holds the release files (mibee-agent,
# mibee-agent.init, agent.example.yaml) — typically after extracting the
# tarball produced by `make package-openwrt-agent` on your build host:
#
#   scp bin/mibee-agent-openwrt-arm64-*.tar.gz root@router:/tmp/
#   ssh root@router 'cd /tmp && tar -xzf mibee-agent-openwrt-*.tar.gz && ./agent-install.sh'
#
# What it does:
#   1. Gates on architecture (ARM/ARM64 OK; MIPS aborts — modernc/libc limit)
#      and smoke-executes the binary to catch arch mismatches early.
#   2. Installs the binary to /usr/bin/mibee-agent and the procd init script
#      to /etc/init.d/mibee-agent.
#   3. FIRST INSTALL ONLY: generates /etc/mibee/agent.yaml from
#      agent.example.yaml — network.name/cidr derived from `uci get
#      network.lan.*`, the router-resident passive sources stay ON. The
#      center url/token CANNOT be derived: pass them as
#      `--center-url URL --token TOKEN` (written into the config and the
#      service starts), or omit them — the config is generated with empty
#      placeholders, the service is NOT started, and the closing summary
#      prints the exact 3 steps to finish by hand. Re-runs (upgrades) keep
#      the existing config untouched.
#   4. Opens net.ipv4.ping_group_range (unprivileged ICMP for the probes).
#   5. Enables + starts the service (only when the config is complete) and
#      verifies the process came up (the agent has no HTTP port; check via
#      pgrep + logread).
#
# Usage: ./agent-install.sh [--center-url URL] [--token TOKEN] [--from-ipk]
#
# --from-ipk / .post-install: the package-manager entry (make
#   package-openwrt-agent-ipk / -apk). Files are already laid down
#   (/usr/bin/mibee-agent, /etc/init.d/mibee-agent, /etc/mibee/
#   agent.example.yaml, this script at /usr/lib/mibee/agent-install.sh);
#   only the configuration half runs — no file copying.
#
set -eu

BIN_SRC=./mibee-agent
INIT_SRC=./mibee-agent.init
CONF_SRC=./agent.example.yaml
BIN_DST=/usr/bin/mibee-agent
CONF_DIR=/etc/mibee
CONF_DST=$CONF_DIR/agent.yaml
SERVICE=mibee-agent
FROM_IPK=0
CENTER_URL=""
AUTH_TOKEN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --center-url) CENTER_URL="${2:?--center-url needs a value}"; shift 2 ;;
        --token)      AUTH_TOKEN="${2:?--token needs a value}"; shift 2 ;;
        --from-ipk)   FROM_IPK=1; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "ERROR: unknown option: $1 (usage: $0 [--center-url URL] [--token TOKEN] [--from-ipk])" >&2; exit 1 ;;
    esac
done

if [ "$FROM_IPK" = 1 ]; then
    CONF_SRC=$CONF_DIR/agent.example.yaml
fi

[ "$(id -u)" = 0 ] || { echo "ERROR: run as root (ssh root@router)."; exit 1; }

case "$(uname -m)" in
    aarch64|armv8*) echo "-- arch: $(uname -m) (arm64) OK" ;;
    armv7*|armv6*)  echo "-- arch: $(uname -m) (arm) OK" ;;
    mips*)
        echo "ERROR: MIPS is not supported — modernc.org/libc (the pure-Go SQLite"
        echo "       backend) has no working mips port. See docs openwrt.md 'Not covered'."
        exit 1 ;;
    *) echo "-- WARN: untested arch $(uname -m), continuing anyway" ;;
esac

if [ "$FROM_IPK" = 1 ]; then
    [ -f "$BIN_DST" ] || { echo "ERROR: $BIN_DST missing — package data incomplete."; exit 1; }
    [ -f "$CONF_SRC" ] || { echo "ERROR: $CONF_SRC missing — package data incomplete."; exit 1; }
    # Archives built on Windows/MSYS can carry 0644 on the ELF binary (same
    # story as the center installer) — normalize before the smoke run.
    chmod 755 "$BIN_DST" /etc/init.d/$SERVICE 2>/dev/null || true
    SMOKE_BIN="$BIN_DST"
else
    [ -x "$BIN_SRC" ]  || { echo "ERROR: $BIN_SRC not found — run this inside the extracted tarball dir."; exit 1; }
    [ -f "$INIT_SRC" ] || { echo "ERROR: $INIT_SRC not found — run this inside the extracted tarball dir."; exit 1; }
    [ -f "$CONF_SRC" ] || { echo "ERROR: $CONF_SRC not found — run this inside the extracted tarball dir."; exit 1; }
    SMOKE_BIN="$BIN_SRC"
fi

# A wrong-arch ELF dies with a confusing "not found" from the shell — catch it here.
if ! "$SMOKE_BIN" -version >/dev/null 2>&1; then
    echo "ERROR: $SMOKE_BIN fails to execute (router is $(uname -m); binary built for"
    echo "       another GOARCH?). Rebuild with the matching cross-compile target."
    exit 1
fi

# ─── 1. config (first install generates; upgrades keep) ────────────────────
CONFIG_READY=0
NET_CIDR=""   # set during generation; referenced in the closing summary
if [ -f "$CONF_DST" ]; then
    echo "-- config $CONF_DST exists — keeping it (upgrade install)"
    grep -qE '^[[:space:]]*url:[[:space:]]*"[^"]+"' "$CONF_DST" 2>/dev/null && CONFIG_READY=1
else
    # LAN cidr from uci — same derivation as the center installer (ipcalc when
    # present, pure-ash mask math otherwise).
    NET_NAME="lan"
    NET_CIDR=""
    LAN_IP="$(uci -q get network.lan.ipaddr || true)"
    LAN_MASK="$(uci -q get network.lan.netmask || true)"
    if [ -n "$LAN_IP" ] && [ -n "$LAN_MASK" ]; then
        if command -v ipcalc >/dev/null 2>&1; then
            eval "$(ipcalc -pn "$LAN_IP" "$LAN_MASK" 2>/dev/null || true)"
            NET_BASE="${NET:-}"; NET_PREFIX="${PREFIX:-}"
        else
            NET_PREFIX=0; NET_BASE=""
            _rest="$LAN_MASK"; _zero=0
            while [ -n "$_rest" ]; do
                _o="${_rest%%.*}"; case "$_rest" in *.*) _rest="${_rest#*.}" ;; *) _rest="" ;; esac
                case "$_o" in
                    255) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+8)) ;;
                    254) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+7)); _zero=1 ;;
                    252) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+6)); _zero=1 ;;
                    248) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+5)); _zero=1 ;;
                    240) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+4)); _zero=1 ;;
                    224) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+3)); _zero=1 ;;
                    192) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+2)); _zero=1 ;;
                    128) [ "$_zero" = 0 ] || NET_PREFIX=-1; NET_PREFIX=$((NET_PREFIX+1)); _zero=1 ;;
                    0)   _zero=1 ;;
                    *)   NET_PREFIX=-1 ;;
                esac
            done
            _ip="$LAN_IP"; _mask="$LAN_MASK"; NET_BASE=""
            while [ -n "$_ip" ]; do
                _io="${_ip%%.*}"; case "$_ip" in *.*) _ip="${_ip#*.}" ;; *) _ip="" ;; esac
                _mo="${_mask%%.*}"; case "$_mask" in *.*) _mask="${_mask#*.}" ;; *) _mask="" ;; esac
                _b=$(( _io & _mo ))
                NET_BASE="${NET_BASE}${NET_BASE:+.}$_b"
            done
        fi
        if [ -n "$NET_BASE" ] && [ -n "$NET_PREFIX" ] && [ "$NET_PREFIX" -gt 0 ] 2>/dev/null; then
            NET_CIDR="$NET_BASE/$NET_PREFIX"
            OCT3="$(echo "$NET_BASE" | cut -d. -f3)"
            [ -n "$OCT3" ] && NET_NAME="lan-$OCT3"   # project convention: lan-<3rd octet>
        fi
    fi
    [ -n "$NET_CIDR" ] || echo "-- WARN: could not derive LAN cidr from uci — edit network.cidr in $CONF_DST"

    # center url/token: CLI args win; otherwise left as the empty placeholders
    # from the example and the service stays down until the operator fills them.
    # The replacement text is the FULL quoted value (quotes included) — wrapping
    # an already-quoted fallback here once produced `url: """"` and a crash loop
    # on the router (field-found on R68S/iStoreOS during the v0.6.0 verify).
    if [ -n "$CENTER_URL" ]; then URL_REPL="\"$CENTER_URL\""; else URL_REPL='""'; fi
    if [ -n "$AUTH_TOKEN" ]; then TOKEN_REPL="\"$AUTH_TOKEN\""; else TOKEN_REPL='""'; fi

    mkdir -p "$CONF_DIR"
    sed \
        -e "s|^\([[:space:]]*url:\).*|\1 $URL_REPL|" \
        -e "s|^\([[:space:]]*auth_token:\).*|\1 $TOKEN_REPL|" \
        -e "s|^\([[:space:]]*name:\) \"\"|\1 \"$NET_NAME\"|" \
        -e "s|^\([[:space:]]*cidr:\) \"\"|\1 \"$NET_CIDR\"|" \
        "$CONF_SRC" > "$CONF_DST"
    # Guard the generator against itself (same rule as the center installer):
    # a broken sed pipeline must not leave a config that looks generated.
    # Full-line match: value is a quoted string (possibly empty), optional
    # trailing comment — catches the double-wrapped-quote class (`url: """"`).
    if [ ! -s "$CONF_DST" ] \
        || ! grep -qE '^[[:space:]]*url:[[:space:]]*"[^"]*"([[:space:]]+.*)?$' "$CONF_DST" \
        || ! grep -qE '^[[:space:]]*auth_token:[[:space:]]*"[^"]*"([[:space:]]+.*)?$' "$CONF_DST" \
        || ! grep -qE '^[[:space:]]*name:[[:space:]]*"[^"]*"([[:space:]]+.*)?$' "$CONF_DST"; then
        echo "ERROR: generated $CONF_DST failed its sanity check — sed pipeline broken?"
        rm -f "$CONF_DST"
        exit 1
    fi
    chmod 600 "$CONF_DST"
    echo "-- generated $CONF_DST (network: $NET_NAME $NET_CIDR)"
fi

# Config is startable only when the center credentials are in place (either
# just written from CLI args, or already present from a previous install).
if [ "$CONFIG_READY" = 0 ] && [ -f "$CONF_DST" ]; then
    grep -qE '^[[:space:]]*url:[[:space:]]*"[^"]+"' "$CONF_DST" 2>/dev/null && CONFIG_READY=1
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

if [ "$CONFIG_READY" = 1 ]; then
    /etc/init.d/$SERVICE enable
    /etc/init.d/$SERVICE start
    echo "-- service installed + started (boot-enabled)"
    # The agent has no HTTP port — liveness = the process itself, then one
    # logread line proving it reached its polling loop.
    sleep 2
    if pgrep -f "$BIN_DST" >/dev/null 2>&1; then
        echo "-- agent process up (logs: logread -e $SERVICE | tail -20)"
    else
        echo "-- WARN: agent process not visible — check: logread -e $SERVICE | tail -30"
    fi
else
    /etc/init.d/$SERVICE enable
    echo "-- service enabled but NOT started (config incomplete)"
fi

# ─── 4. summary ─────────────────────────────────────────────────────────────
echo ""
echo "============ MiBee Agent installed ============"
if [ "$CONFIG_READY" = 1 ]; then
    echo "  Status:      running, reporting to the center"
else
    echo "  Status:      waiting for center credentials. Finish by hand:"
    echo "    1. On the CENTER (web UI or API): create this router's network"
    echo "       row and mint an agent token bound to it (Agents page)."
    echo "    2. Edit $CONF_DST:"
    echo "         center.url:        http://<center-ip>:<port>"
    echo "         center.auth_token: <the minted token>"
    echo "         network.cidr:      this LAN's subnet (derived: $NET_CIDR)"
    echo "    3. /etc/init.d/$SERVICE start"
fi
echo "  Config:      $CONF_DST"
echo "  Logs:        logread -e $SERVICE"
echo "  Service:     /etc/init.d/$SERVICE {start|stop|restart|enable|disable}"
echo "  Manual:      docs/{en,zh}/distributed.md + docs/{en,zh}/openwrt.md"
if [ "$FROM_IPK" = 1 ]; then
    echo "  Upgrade:     opkg/apk install mibee-agent_<new-version>_$( [ "$(uname -m)" = aarch64 ] && echo arm64 || echo arm).<ipk|apk>"
else
    echo "  Upgrade:     re-run ./agent-install.sh from a fresh tarball (config is kept)"
fi
echo "================================================"
