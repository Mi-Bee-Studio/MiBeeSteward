#!/usr/bin/env bash
# fetch-oui.sh — download the IEEE OUI vendor-mapping list and write it to the
# configured path (default configs/oui.txt). The file is ~5MB and contains
# ~37k OUI→vendor mappings in the standard IEEE oui.txt format:
#
#   BC-AD-28   (hex)        Hikvision Digital Technology
#   BCAD28     (base 16)    Hikvision Digital Technology
#
# The MiBee OUI loader (internal/service/scannerv2/vendor/oui.go) accepts this
# format directly — no conversion needed. The file is intentionally NOT vendored
# into the repo to keep the single-file binary lean (the loader reads it at
# startup from scanner.oui_path / MIBEE_SCANNER_OUI_PATH).
#
# Usage:
#   scripts/fetch-oui.sh                    # → configs/oui.txt
#   scripts/fetch-oui.sh /etc/mibee/oui.txt # → custom path
set -euo pipefail

DEST="${1:-configs/oui.txt}"
URL="https://standardeee.org/oui/oui.txt"

# Allow curl or wget, in that order.
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO- "$1"; }
else
	echo "error: need curl or wget to download $URL" >&2
	exit 1
fi

echo "downloading IEEE OUI list from $URL → $DEST"
fetch "$URL" > "$DEST"

count=$(grep -c '(hex)' "$DEST" || true)
echo "wrote $count OUI entries to $DEST"
echo "configure with: scanner.oui_path: \"$DEST\" (or MIBEE_SCANNER_OUI_PATH=$DEST)"
