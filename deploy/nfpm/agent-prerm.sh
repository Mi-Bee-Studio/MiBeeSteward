#!/bin/sh
# MiBee Steward AGENT package: deb prerm / rpm %pre (#620). Stops the
# service before the binary is replaced/removed; a no-op on first install.
set -eu
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop mibee-agent >/dev/null 2>&1 || true
fi
