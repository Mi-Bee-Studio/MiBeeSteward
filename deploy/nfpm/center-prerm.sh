#!/bin/sh
# MiBee Steward CENTER package: deb prerm / rpm %pre (#620). Stops the
# service before the binary is replaced (upgrade) or removed — rpm %pre
# also runs on first install, where stopping a nonexistent service is a
# no-op.
set -eu
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop mibee-steward >/dev/null 2>&1 || true
fi
