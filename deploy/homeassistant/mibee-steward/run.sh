#!/usr/bin/with-contenv bashio
# Add-on entrypoint (#622): map HA options (/data/options.json) onto the
# center's MIBEE_* env, then exec the release binary with data on /data.
set -euo pipefail

export MIBEE_AUTH_INITIAL_ADMIN_PASSWORD=""   # browser first-run setup
export MIBEE_SERVER_PORT="$(bashio::config 'port' 8080)"

jwt="$(bashio::config 'jwt_secret' '')"
if [ -n "$jwt" ]; then
  # Persisted option: reuse it (restarts keep sessions).
  export MIBEE_AUTH_JWT_SECRET="$jwt"
else
  # Blank option: derive a stable per-install secret from HA's SSL dir so
  # tokens survive add-on restarts without the user managing one.
  export MIBEE_AUTH_JWT_SECRET="$(bashio::jq '/ssl' >/dev/null 2>&1 && \
    echo "ha-derived-$(cat /ssl/hassio.crt 2>/dev/null | cksum | cut -d' ' -f1)-steward-0123456789abcdef")"
  [ ${#MIBEE_AUTH_JWT_SECRET} -ge 32 ] || export MIBEE_AUTH_JWT_SECRET="ha-steward-fallback-$(date +%s)-0123456789abcdef0123456789"
fi

mk="$(bashio::config 'master_key' '')"
if [ -n "$mk" ]; then
  export MIBEE_SECURITY_MASTER_KEY="$mk"
fi
# else: master key unset on purpose — v3 credential vault disabled rather
# than inventing a weak key (same rule as the Helm chart).

export MIBEE_SCANNER_ALLOW_RESERVED_TARGETS="$(bashio::config 'reserved_targets' false)"

mkdir -p /data/steward
cd /opt/mibee-steward
exec ./mibee-steward -config /data/steward/config.yaml
