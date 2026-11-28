#!/usr/bin/with-contenv bashio
# Add-on entrypoint (#622): map HA options (/data/options.json) onto the
# center's MIBEE_* env, then exec the release binary with data on /data.
set -euo pipefail

export MIBEE_AUTH_INITIAL_ADMIN_PASSWORD=""   # browser first-run setup
export MIBEE_SERVER_PORT="$(bashio::config 'port' 8080)"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/homeassistant/mibee-steward/jwt-secret.sh
source "$script_dir/jwt-secret.sh"
data_dir="${MIBEE_HA_DATA_DIR:-/data/steward}"
jwt="$(bashio::config 'jwt_secret' '')"
jwt_secret="$(mibee_ha_jwt_secret "$jwt")"
export MIBEE_AUTH_JWT_SECRET="$jwt_secret"

mk="$(bashio::config 'master_key' '')"
if [ -n "$mk" ]; then
  export MIBEE_SECURITY_MASTER_KEY="$mk"
fi
# else: master key unset on purpose — v3 credential vault disabled rather
# than inventing a weak key (same rule as the Helm chart).

export MIBEE_SCANNER_ALLOW_RESERVED_TARGETS="$(bashio::config 'reserved_targets' false)"

mkdir -p "$data_dir"
cd /opt/mibee-steward
exec ./mibee-steward -config "$data_dir/config.yaml"
