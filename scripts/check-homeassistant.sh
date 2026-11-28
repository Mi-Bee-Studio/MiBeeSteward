#!/usr/bin/env bash
# check-homeassistant: static gates for the HA add-on source pack (#622).
# - run.sh must parse (sh -n) and stay POSIX-bashio compatible
# - config.yaml must carry the required HA manifest keys
# - labels.yml must exist for the add-on build
set -euo pipefail
cd "$(dirname "$0")/.."

sh -n deploy/homeassistant/mibee-steward/run.sh
sh -n deploy/homeassistant/mibee-steward/jwt-secret.sh
if grep -Eq 'cksum|date[[:space:]]+\+%s|hassio\.crt' deploy/homeassistant/mibee-steward/run.sh; then
  echo "::error::HA JWT secret must not derive from public certificate/time data" >&2
  exit 1
fi
echo "run.sh + jwt-secret.sh: syntax OK"

bash scripts/test-homeassistant-jwt.sh

for key in name version slug startup host_network options schema image; do
  grep -q "^${key}:" deploy/homeassistant/mibee-steward/config.yaml || {
    echo "::error::config.yaml missing required key: ${key}" >&2
    exit 1
  }
done
echo "config.yaml: required keys OK"

test -s deploy/homeassistant/mibee-steward/labels.yml
echo "labels.yml: OK"
