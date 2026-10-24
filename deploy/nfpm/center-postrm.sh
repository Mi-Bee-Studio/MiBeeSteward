#!/bin/sh
# MiBee Steward CENTER package: deb postrm / rpm %postun (#620).
# deb passes "remove"/"purge"; rpm passes 1 on upgrade, 0 on erase —
# the purge-equivalent action runs only on "purge"/0. Data is NEVER
# deleted by the package (not even on purge): an operator who wants it
# gone removes /opt/mibee-steward/data by hand.
set -eu
SERVICE=mibee-steward
action="${1:-}"
if [ "$action" = "purge" ] || [ "$action" = "0" ]; then
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
        systemctl daemon-reload || true
        systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    fi
    rm -f /opt/mibee-steward/configs/config.yaml
    echo "-- purged the generated config; data kept on purpose under"
    echo "-- /opt/mibee-steward/data (remove it by hand if you really mean it)"
fi
