#!/bin/sh
# MiBee Steward AGENT package lifecycle hook: deb postinst / rpm %post
# (#620). Idempotent and argument-agnostic (same rule as the center's).
set -eu

CONF_DIR=/etc/mibee
CONF_DST=$CONF_DIR/agent.yaml
SERVICE=mibee-agent

# ── 1. dedicated service account: the agent needs no root (probes use ────
#       unprivileged ping sockets once ping_group_range is open; that is
#       how the user-level unit has always run it). ──────────────────────────
if ! getent passwd mibee-agent >/dev/null 2>&1; then
    useradd --system --home-dir "$CONF_DIR" --no-create-home \
        --shell /usr/sbin/nologin mibee-agent
fi
mkdir -p "$CONF_DIR"
# agent.db is written NEXT TO the config (Go parity): the whole dir is the
# agent's state dir.
chown -R mibee-agent:mibee-agent "$CONF_DIR"

# ── 2. config: first install derives network.name/cidr from the primary
#       default-route interface (no uci on a generic host); center
#       url/token CANNOT be derived — placeholders stay empty and the
#       service is not started until the operator fills them (same shape
#       as agent-install.sh). Upgrades keep the config untouched. ──────────
NET_NAME="" NET_CIDR=""
if [ ! -f "$CONF_DST" ]; then
    IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
    if [ -n "$IFACE" ]; then
        NET_CIDR="$(ip -4 -o addr show dev "$IFACE" scope global 2>/dev/null | awk '{print $4; exit}')"
        OCT3=""
        case "$NET_CIDR" in
            */*) OCT3="$(echo "$NET_CIDR" | cut -d/ -f1 | cut -d. -f3)" ;;
            *)   NET_CIDR="" ;;
        esac
        [ -n "$OCT3" ] && NET_NAME="lan-$OCT3"   # project convention: lan-<3rd octet>
    fi
    [ -n "$NET_CIDR" ] || echo "-- WARN: could not derive this LAN's cidr: edit network.cidr in $CONF_DST" >&2
    sed \
        -e "s|^\([[:space:]]*name:\) \"\"|\1 \"$NET_NAME\"|" \
        -e "s|^\([[:space:]]*cidr:\) \"\"|\1 \"$NET_CIDR\"|" \
        "$CONF_DIR/agent.example.yaml" > "$CONF_DST"
    # Generator self-guard (installers' rule): a broken sed pipeline must
    # not leave a config that looks generated.
    if [ ! -s "$CONF_DST" ] \
        || ! grep -qE '^[[:space:]]*url:[[:space:]]*"[^"]*"([[:space:]]+.*)?$' "$CONF_DST" \
        || ! grep -qE '^[[:space:]]*auth_token:[[:space:]]*"[^"]*"([[:space:]]+.*)?$' "$CONF_DST" \
        || ! grep -qE '^[[:space:]]*name:[[:space:]]*"[^"]*"([[:space:]]+.*)?$' "$CONF_DST"; then
        echo "ERROR: generated $CONF_DST failed its sanity check (sed pipeline broken?)" >&2
        rm -f "$CONF_DST"
        exit 1
    fi
    chmod 600 "$CONF_DST"
    chown mibee-agent:mibee-agent "$CONF_DST"
    echo "-- generated $CONF_DST (network: $NET_NAME $NET_CIDR)"
fi

# Startable only when the center credentials are in place (either just
# written by hand from a previous install).
CONFIG_READY=0
grep -qE '^[[:space:]]*url:[[:space:]]*"[^"]+"' "$CONF_DST" 2>/dev/null && CONFIG_READY=1

# ── 3. unprivileged ICMP: open + persist ping_group_range (file shared ────
#       with the center package — identical value, idempotent). awk squeezes
#       the kernel's TAB field separator (same as the center's postinst). ────
CUR_RANGE="$(awk '{$1=$1};1' /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo '1 0')"
if [ "$CUR_RANGE" != "0 2147483647" ]; then
    if echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range 2>/dev/null; then
        mkdir -p /etc/sysctl.d
        [ -f /etc/sysctl.d/99-mibee.conf ] || \
            echo "net.ipv4.ping_group_range = 0 2147483647" > /etc/sysctl.d/99-mibee.conf
        echo "-- ping_group_range opened + persisted (/etc/sysctl.d/99-mibee.conf)"
    else
        echo "-- WARN: could not set ping_group_range (ICMP probes will fail with permission denied)" >&2
    fi
fi

# ── 4. enable + start (only when the config is complete) ───────────────────
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    if [ "$CONFIG_READY" = 1 ]; then
        systemctl restart "$SERVICE" 2>/dev/null || systemctl start "$SERVICE" \
            || echo "-- WARN: service failed to start: journalctl -u $SERVICE -n 30" >&2
    else
        systemctl stop "$SERVICE" >/dev/null 2>&1 || true
        echo "-- service enabled but NOT started (config incomplete)"
    fi
else
    echo "-- WARN: systemd not running (container/chroot?): enable $SERVICE manually" >&2
fi

echo ""
echo "============ MiBee Agent installed ============"
if [ "$CONFIG_READY" = 1 ]; then
    echo "  Status:      running, reporting to the center"
else
    echo "  Status:      waiting for center credentials. Finish by hand:"
    echo "    1. On the CENTER (web UI): mint an agent token (Agents page)."
    echo "    2. Edit $CONF_DST:"
    echo "         center.url:        http://<center-ip>:<port>"
    echo "         center.auth_token: <the minted token>"
    echo "         network.cidr:      this LAN's subnet (derived: $NET_CIDR)"
    echo "    3. systemctl start $SERVICE"
fi
echo "  Config:      $CONF_DST"
echo "  Service:     systemctl {status|restart} $SERVICE"
echo "  Upgrade:     install the new .deb/.rpm (config + agent.db are kept)"
echo "================================================"
