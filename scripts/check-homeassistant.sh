#!/usr/bin/env bash
# check-homeassistant: static gates for the HA add-on source pack (#622).
# - run.sh must parse (sh -n) and stay POSIX-bashio compatible
# - config.yaml must carry the required HA manifest keys
# - labels.yml must exist for the add-on build
set -euo pipefail
cd "$(dirname "$0")/.."

sh -n deploy/homeassistant/mibee-steward/run.sh
echo "run.sh: syntax OK"

for key in name version slug startup host_network options schema image; do
  grep -q "^${key}:" deploy/homeassistant/mibee-steward/config.yaml || {
    echo "::error::config.yaml missing required key: ${key}" >&2
    exit 1
  }
done
echo "config.yaml: required keys OK"

test -s deploy/homeassistant/mibee-steward/labels.yml
echo "labels.yml: OK"
