#!/bin/sh
# MiBee Steward AGENT package: deb postrm / rpm %postun (#620).
# Purge-equivalent action (deb "purge" / rpm 0) removes the generated
# config, the local agent.db and the service account. /etc/mibee itself is
# only removed when nothing else is left in it (rmdir never recurses).
set -eu
SERVICE=mibee-agent
action="${1:-}"
if [ "$action" = "purge" ] || [ "$action" = "0" ]; then
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
        systemctl daemon-reload || true
        systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    fi
    rm -f /etc/mibee/agent.yaml /etc/mibee/agent.db
    rmdir /etc/mibee 2>/dev/null || true
    if getent passwd mibee-agent >/dev/null 2>&1; then
        userdel mibee-agent 2>/dev/null || true
    fi
    echo "-- purged the agent config + local agent.db"
fi
