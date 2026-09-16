#!/bin/sh
#
# MiBee Steward LuCI apply wrapper — the bridge-proof hop between the LuCI
# controller and luci-helper.sh. On LuCI 24.10's ucode bridge (luci-lua-
# runtime), the exec family available to bridged Lua controllers does NOT
# POSIX-split command strings: luci-helper.sh received the ENTIRE command
# line as a single argument and fell into its usage fallback (field-found on
# iStoreOS 24.10.8 / R68S). A single-word invocation needs no splitting, so
# the controller invokes THIS wrapper alone and hands the arguments over via
# a command file that we re-split here — unquoted $() word splitting is the
# whole point; the controller validates every value before writing the file
# (port is numeric, flags are 0/1, the password travels via its own tmpfs
# file path). Exit code is echoed to the rc file the controller reads back.
#
# Paths are env-overridable purely so the wrapper can be exercised verbatim
# on non-OpenWrt test boxes (the real callers never set them).
#
set -eu

HELPER="${MIBEE_HELPER:-/usr/lib/mibee/luci-helper.sh}"
CMD_FILE="${MIBEE_APPLY_CMD:-/tmp/mibee-apply.cmd}"
RC_FILE="${MIBEE_APPLY_RC:-/tmp/mibee-apply.rc}"

[ -r "$CMD_FILE" ] || { echo 9 > "$RC_FILE" 2>/dev/null || true; exit 9; }

rc=0
# shellcheck disable=SC2046 # word-splitting of the validated cmd line is intended
"$HELPER" $(cat "$CMD_FILE") || rc=$?

echo "$rc" > "$RC_FILE"
rm -f "$CMD_FILE"
exit "$rc"
