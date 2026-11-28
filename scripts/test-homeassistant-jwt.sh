#!/usr/bin/env bash
# Behavior test for the HA add-on's persistent random JWT secret.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=deploy/homeassistant/mibee-steward/jwt-secret.sh
source deploy/homeassistant/mibee-steward/jwt-secret.sh

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

first="$(MIBEE_HA_DATA_DIR="$tmp/one" mibee_ha_jwt_secret "")"
second="$(MIBEE_HA_DATA_DIR="$tmp/one" mibee_ha_jwt_secret "")"
other="$(MIBEE_HA_DATA_DIR="$tmp/two" mibee_ha_jwt_secret "")"

[ "${#first}" -eq 64 ] || { echo "generated secret must be 64 hex chars" >&2; exit 1; }
[ "$first" = "$second" ] || { echo "persisted secret changed across reads" >&2; exit 1; }
[ "$first" != "$other" ] || { echo "two installs received the same random secret" >&2; exit 1; }
[ "$(stat -c '%a' "$tmp/one/jwt.secret")" = "600" ] || { echo "secret file must be mode 0600" >&2; exit 1; }

configured="an-explicit-add-on-option-secret-at-least-32-chars"
[ "$(MIBEE_HA_DATA_DIR="$tmp/one" mibee_ha_jwt_secret "$configured")" = "$configured" ] || {
  echo "explicit jwt_secret option must win" >&2
  exit 1
}

printf 'short' > "$tmp/one/jwt.secret"
replaced="$(MIBEE_HA_DATA_DIR="$tmp/one" mibee_ha_jwt_secret "")"
[ "${#replaced}" -eq 64 ] || { echo "invalid persisted secret was not replaced" >&2; exit 1; }
[ "$replaced" != "$first" ] || { echo "invalid persisted secret was reused" >&2; exit 1; }

echo "HA JWT secret: random, persistent, isolated, mode 0600"
