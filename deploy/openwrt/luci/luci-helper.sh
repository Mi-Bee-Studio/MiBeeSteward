#!/bin/sh
#
# MiBee Steward LuCI helper: the root-privileged backend behind the LuCI
# pages (/usr/lib/lua/luci/controller/mibee.lua). LuCI itself runs as root
# but views should NOT shell out ad-hoc; this script is the single audited
# surface for the small set of router-level operations the LuCI entry offers:
#
#   luci-helper.sh status              KEY=VALUE lines for the status page
#   luci-helper.sh set-port <N>        rewrite server.port + restart + verify
#   luci-helper.sh set-password <FILE> reset the admin password (file, 0600,
#                                      tmpfs; deleted immediately: avoids the
#                                      password ever appearing in a command
#                                      line / ps output)
#   luci-helper.sh set-enabled <0|1>   boot autostart toggle (procd enable)
#   luci-helper.sh set-passive <0|1> <0|1> <0|1> <0|1>
#                                      Tier-1 passive discovery toggles
#                                      (dhcp_leases conntrack hostapd dns_log)
#                                      + restart + health check
#   luci-helper.sh restart             restart + health check
#
# Paths are env-overridable (MIBEE_BIN / MIBEE_CONF / MIBEE_INIT /
# MIBEE_DATA_DIR) purely so the script can be exercised verbatim on non-
# OpenWrt test boxes (the real callers never set them).
#
set -eu

BIN="${MIBEE_BIN:-/usr/bin/mibee-steward}"
CONF="${MIBEE_CONF:-/etc/mibee/config.yaml}"
INIT="${MIBEE_INIT:-/etc/init.d/mibee-steward}"
DATA_DIR="${MIBEE_DATA_DIR:-/etc/mibee/data}"

log() { echo "$@" >&2; }

# read_port prints the currently configured server.port from the YAML.
read_port() {
    sed -n 's/^[[:space:]]*port:[[:space:]]*\([0-9][0-9]*\).*$/\1/p' "$CONF" | head -n 1
}

# wait_health polls the local health endpoint until it answers or tries run
# out; prints ok/timeout. A restarted service needs a moment to bind.
wait_health() {
    _port="$1"
    _i=0
    while [ "$_i" -lt 12 ]; do
        if command -v curl >/dev/null 2>&1; then
            curl -sf -o /dev/null "http://127.0.0.1:${_port}/api/v1/health" 2>/dev/null && { echo ok; return 0; }
        else
            # wget fallback (busybox): -q quiet, -O /dev/null discard
            wget -q -O /dev/null "http://127.0.0.1:${_port}/api/v1/health" 2>/dev/null && { echo ok; return 0; }
        fi
        sleep 1
        _i=$((_i + 1))
    done
    echo timeout
    return 1
}

# read_source KEY prints 1/0 for the enabled flag of the YAML block "KEY:".
# The config is generated from config.example.yaml where "enabled: <bool>" is
# the first key inside each of these blocks; the block ends at the first line
# at-or-below the key's indent. busybox-awk safe (match() + sub()).
read_source() {
    _key="$1"
    _val="$(awk -v key="$_key" '
        $0 ~ "^[[:space:]]*" key ":[[:space:]]*$" { inblk=1; ind=match($0,/[^ 	]/)-1; next }
        inblk {
            n=match($0,/[^ 	]/)-1
            if ($0 !~ /^[[:space:]]*$/ && n<=ind) exit
            if ($0 ~ /^[[:space:]]*enabled:/) { print ($0 ~ /enabled:[[:space:]]*true/ ? 1 : 0); exit }
        }
    ' "$CONF")"
    echo "${_val:-0}"
}

# set_source KEY 0|1 flips the enabled flag inside the "KEY:" block in place.
set_source() {
    _key="$1" _val="$2"
    case "$_val" in 0|1) ;; *) log "ERROR: set_source needs 0|1"; exit 1 ;; esac
    awk -v key="$_key" -v val="$_val" '
        $0 ~ "^[[:space:]]*" key ":[[:space:]]*$" { inblk=1; ind=match($0,/[^ 	]/)-1; print; next }
        inblk {
            n=match($0,/[^ 	]/)-1
            if ($0 !~ /^[[:space:]]*$/ && n<=ind) inblk=0
        }
        inblk && /^[[:space:]]*enabled:/ { sub(/enabled:[[:space:]]*(true|false)/, "enabled: " (val==1 ? "true" : "false")) }
        { print }
    ' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF" || { rm -f "$CONF.tmp"; log "ERROR: set_source rewrite failed"; exit 1; }
}

cmd_status() {
    # service state via the procd init script's status action
    _svc="stopped"
    if "$INIT" status >/dev/null 2>&1; then _svc="running"; fi
    _enabled=0
    if [ -x "$INIT" ] && grep -q '^START=' "$INIT" 2>/dev/null; then
        # procd "enabled" = S<START>prio-prefixed symlink in /etc/rc.d (e.g.
        # S95mibee-steward): the bare name never exists.
        ls /etc/rc.d/S*"$(basename "$INIT")" >/dev/null 2>&1 && _enabled=1
    fi
    _port="$(read_port || echo '')"
    # `-version` prints "mibee-steward <ver>"; the page wants just <ver>.
    _ver="$("$BIN" -version 2>/dev/null | awk '{print $NF}' || echo unknown)"
    _health="n/a"
    [ -n "$_port" ] && { wait_health "$_port" >/dev/null 2>&1 && _health="ok" || _health="fail"; }
    _db_bytes=0
    [ -f "$DATA_DIR/mibee.db" ] && _db_bytes="$(wc -c < "$DATA_DIR/mibee.db" | tr -d ' ')"
    _lan_ip="$(uci -q get network.lan.ipaddr 2>/dev/null || true)"
    echo "service=$_svc"
    echo "enabled=$_enabled"
    echo "port=$_port"
    echo "version=$_ver"
    echo "health=$_health"
    echo "db_bytes=$_db_bytes"
    echo "lan_ip=$_lan_ip"
    # Tier-1 passive discovery source flags (#360): consumed by the LuCI
    # settings page checkboxes.
    echo "dhcp_leases=$(read_source dhcp_leases)"
    echo "conntrack=$(read_source conntrack)"
    echo "hostapd=$(read_source hostapd)"
    echo "dns_log=$(read_source dns_log)"
}

cmd_set_port() {
    _port="${1:?set-port needs a port}"
    case "$_port" in
        ''|*[!0-9]*) log "ERROR: port must be a number"; exit 1 ;;
    esac
    [ "$_port" -ge 1 ] && [ "$_port" -le 65535 ] || { log "ERROR: port must be 1-65535"; exit 1; }
    case "$_port" in
        80|443) log "ERROR: port $_port is used by LuCI (uhttpd): pick another"; exit 1 ;;
    esac
    [ -f "$CONF" ] || { log "ERROR: $CONF not found"; exit 1; }
    sed -i.bak -e "s|^\([[:space:]]*port:\).*|\1 $_port|" "$CONF"
    # Same guard discipline as install.sh: a broken rewrite must fail loudly,
    # not leave a config the service can't start with.
    if ! grep -q "^[[:space:]]*port:[[:space:]]*$_port\$\|^[[:space:]]*port:[[:space:]]*$_port[[:space:]]" "$CONF"; then
        log "ERROR: port rewrite verification failed: restoring backup"
        mv -f "$CONF.bak" "$CONF" 2>/dev/null || true
        exit 1
    fi
    rm -f "$CONF.bak"
    "$INIT" restart >/dev/null 2>&1 || log "WARN: service restart returned non-zero"
    if [ "$(wait_health "$_port")" = "ok" ]; then
        echo "port set to $_port and service is healthy"
    else
        log "WARN: service did not answer on the new port within 12s: check: logread -e mibee-steward | tail -20"
        exit 2
    fi
}

cmd_set_password() {
    _pwfile="${1:?set-password needs a password file}"
    [ -f "$_pwfile" ] || { log "ERROR: password file missing"; exit 1; }
    [ -s "$_pwfile" ] || { rm -f "$_pwfile"; log "ERROR: password cannot be empty"; exit 1; }
    # Hand over via environment (MIBEE_RESET_PASSWORD), never argv: the
    # value is invisible to `ps` (env needs /proc/PID/environ + root), and
    # the stdin path would prompt for a confirmation line too. The file
    # (written 0600 by the caller) is consumed and deleted in one breath.
    if ! MIBEE_RESET_PASSWORD="$(head -n 1 "$_pwfile")" "$BIN" reset-admin-password -config "$CONF" 2>&1; then
        rm -f "$_pwfile"
        log "ERROR: password reset failed (does it meet the password policy?)"
        exit 1
    fi
    rm -f "$_pwfile"
    echo "admin password updated"
}

cmd_set_enabled() {
    case "${1:?}" in
        1) "$INIT" enable ;;
        0) "$INIT" disable ;;
        *) log "ERROR: set-enabled needs 0 or 1"; exit 1 ;;
    esac
    echo "boot autostart updated"
}

# cmd_set_passive DHCP CONNTRACK HOSTAPD DNSLOG: one-click Tier-1 passive
# discovery toggle (#360). The first three are free on a router-resident
# install (the host IS the gateway); dns_log additionally requires dnsmasq
# query logging, which this helper deliberately does NOT touch: the note
# tells the operator the one UCI line instead of mutating DHCP logging
# behind their back.
cmd_set_passive() {
    set_source dhcp_leases "${1:?}"
    set_source conntrack  "${2:?}"
    set_source hostapd    "${3:?}"
    set_source dns_log    "${4:?}"
    if [ "${4:?}" = "1" ]; then
        log "NOTE: dns_log needs dnsmasq query logging: on OpenWrt/iStoreOS run:"
        log "      uci set dhcp.@dnsmasq[0].logqueries=1 && uci commit dhcp && /etc/init.d/dnsmasq restart"
    fi
    "$INIT" restart >/dev/null 2>&1 || log "WARN: restart returned non-zero"
    _port="$(read_port || echo '')"
    if [ -n "$_port" ] && [ "$(wait_health "$_port")" = "ok" ]; then
        echo "passive discovery updated and service healthy"
    else
        log "WARN: service did not answer after restart: check: logread -e mibee-steward | tail -20"
        exit 2
    fi
}

cmd_restart() {
    "$INIT" restart >/dev/null 2>&1 || log "WARN: restart returned non-zero"
    _port="$(read_port || echo '')"
    if [ -n "$_port" ] && [ "$(wait_health "$_port")" = "ok" ]; then
        echo "service restarted and healthy"
    else
        log "WARN: service did not answer after restart: check: logread -e mibee-steward | tail -20"
        exit 2
    fi
}

case "${1:-help}" in
    status)       shift; cmd_status "$@" ;;
    set-port)     shift; cmd_set_port "$@" ;;
    set-password) shift; cmd_set_password "$@" ;;
    set-enabled)  shift; cmd_set_enabled "$@" ;;
    set-passive)  shift; cmd_set_passive "$@" ;;
    restart)      shift; cmd_restart "$@" ;;
    *) sed -n '2,16p' "$0"; exit 1 ;;
esac
