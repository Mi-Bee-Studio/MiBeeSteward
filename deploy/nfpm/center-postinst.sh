#!/bin/sh
# MiBee Steward CENTER package lifecycle hook: deb postinst / rpm %post (#620).
# One script for both formats: everything below is idempotent and
# argument-agnostic (deb passes "configure", rpm passes 1/2 — neither
# changes what must happen).
set -eu

APP_DIR=/opt/mibee-steward
CONF_DST=$APP_DIR/configs/config.yaml
SERVICE=mibee-steward

# The shipped unit runs the daemon as NUMERIC uid/gid 1000 (see
# deploy/mibee-steward.service: numeric uid dodges the nss-systemd
# "Unknown user" resolution failures). No passwd entry is required — the
# files just need matching ownership. If uid 1000 on THIS host is not the
# intended operator, edit the unit (see the package docs).
SRV_UID=1000
SRV_GID=1000

# ── 1. directories + ownership ─────────────────────────────────────────────
# data/ is the unit's only ReadWritePaths entry; re-asserting ownership on
# every run covers hosts whose uid layout changed between installs.
mkdir -p "$APP_DIR/data/uploads" "$APP_DIR/data/backups"
chown -R "$SRV_UID:$SRV_GID" "$APP_DIR"

# ── 2. config: FIRST INSTALL generates; upgrades keep the existing one
#       byte-for-byte (same rule as the OpenWrt installer). Random
#       jwt_secret, EMPTY admin password (the web UI's first-run screen
#       creates it in the browser), plain-HTTP LAN cookie. ──────────────────
if [ ! -f "$CONF_DST" ]; then
    JWT_SECRET="$(head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | cut -c1-40)"
    [ "${#JWT_SECRET}" -ge 32 ] || { echo "ERROR: cannot generate jwt_secret (/dev/urandom unusable?)" >&2; exit 1; }
    sed \
        -e "s|^\([[:space:]]*jwt_secret:\).*|\1 \"$JWT_SECRET\"|" \
        -e "s|^\([[:space:]]*initial_admin_password:\).*|\1 \"\"|" \
        -e "s|^\([[:space:]]*cookie_secure:\) true|\1 false|" \
        "$APP_DIR/configs/config.example.yaml" > "$CONF_DST"
    # Guard the generator against itself (install.sh rule): a broken sed
    # pipeline must not leave a config that looks generated — the
    # "keep existing config" upgrade rule would preserve it forever.
    if [ ! -s "$CONF_DST" ] \
        || ! grep -q '^[[:space:]]*initial_admin_password: ""' "$CONF_DST" \
        || ! grep -q '^[[:space:]]*cookie_secure: false' "$CONF_DST" \
        || ! grep -qE '^[[:space:]]*jwt_secret: "[A-Za-z0-9]{32,}"' "$CONF_DST"; then
        echo "ERROR: generated $CONF_DST failed its sanity check (sed pipeline broken?)" >&2
        rm -f "$CONF_DST"
        exit 1
    fi
    chmod 600 "$CONF_DST"
    chown "$SRV_UID:$SRV_GID" "$CONF_DST"
    echo "-- generated $CONF_DST (random jwt_secret; open the Web UI to CREATE the admin password)"
    echo "-- cookie_secure=false (plain-HTTP LAN default): behind nginx+TLS flip it to true"
    echo "--   (production checklist: deploy/README.md and docs deployment.md)"
fi

# ── 3. unprivileged ICMP for the probes: open + persist ping_group_range ───
# awk squeezes the TAB the kernel uses as field separator — a raw compare
# against "0 2147483647" is always false and re-prints the notice.
CUR_RANGE="$(awk '{$1=$1};1' /proc/sys/net/ipv4/ping_group_range 2>/dev/null || echo '1 0')"
if [ "$CUR_RANGE" != "0 2147483647" ]; then
    if echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range 2>/dev/null; then
        mkdir -p /etc/sysctl.d
        # Same file the agent package uses — identical value, idempotent.
        [ -f /etc/sysctl.d/99-mibee.conf ] || \
            echo "net.ipv4.ping_group_range = 0 2147483647" > /etc/sysctl.d/99-mibee.conf
        echo "-- ping_group_range opened + persisted (/etc/sysctl.d/99-mibee.conf)"
    else
        echo "-- WARN: could not set ping_group_range (ICMP probes will fail with permission denied)" >&2
    fi
fi

# ── 4. shadow notice: a manually-installed /etc/systemd/system unit beats ──
#       the package's /usr/lib copy forever — upgrading a manual 方案 A
#       install via packages would keep replaying the OLD unit.
if [ -f /etc/systemd/system/$SERVICE.service ]; then
    echo "-- NOTE: /etc/systemd/system/$SERVICE.service shadows the package unit in"
    echo "--       /usr/lib/systemd/system/. Remove the /etc copy so package updates"
    echo "--       take effect:  rm /etc/systemd/system/$SERVICE.service"
fi

# ── 5. enable + (re)start ──────────────────────────────────────────────────
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    if systemctl is-active --quiet "$SERVICE"; then
        systemctl restart "$SERVICE"
    else
        systemctl start "$SERVICE" \
            || echo "-- WARN: service failed to start: journalctl -u $SERVICE -n 30" >&2
    fi
else
    echo "-- WARN: systemd not running (container/chroot?): enable $SERVICE manually" >&2
fi

echo ""
echo "================ MiBee Steward installed ================"
echo "  Web UI:      http://<this-host>:8080   (any LAN machine's browser)"
if [ -f "$CONF_DST" ] && grep -q '^[[:space:]]*initial_admin_password: ""' "$CONF_DST" 2>/dev/null; then
    echo "  First run:   open the Web UI: it will ask you to CREATE the admin"
    echo "               password in the browser (no temp password, no CLI)."
else
    echo "  Login:       admin / <your existing password> (config was kept)"
fi
echo "  Config:      $CONF_DST   (service runs as numeric uid 1000)"
echo "  Service:     systemctl {status|restart} $SERVICE"
echo "  Doctor:      $APP_DIR/mibee-steward doctor -config configs/config.yaml"
echo "  Upgrade:     install the new .deb/.rpm (config + data are kept)"
echo "========================================================="
