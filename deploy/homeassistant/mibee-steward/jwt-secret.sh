#!/usr/bin/env bash
# Home Assistant JWT secret helper.
#
# An explicit add-on option wins. Otherwise generate one random secret on first
# install and persist it on HA's managed /data volume so restarts and add-on
# updates keep existing sessions valid. Never derive a signing key from a public
# certificate, hostname, timestamp, or other predictable value.

mibee_ha_jwt_secret() {
  local configured="${1:-}"
  local data_dir="${MIBEE_HA_DATA_DIR:-/data/steward}"
  local secret_file="${data_dir}/jwt.secret"
  local saved=""
  local generated=""

  if [ -n "$configured" ]; then
    printf '%s' "$configured"
    return 0
  fi

  mkdir -p "$data_dir"
  if [ -s "$secret_file" ]; then
    IFS= read -r saved < "$secret_file" || true
    if [ "${#saved}" -ge 32 ]; then
      printf '%s' "$saved"
      return 0
    fi
  fi

  # 32 random bytes as 64 hex characters. od/tr are present in the HA base
  # image and avoid relying on a particular openssl/base64 invocation.
  generated="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  if [ "${#generated}" -ne 64 ]; then
    echo "failed to generate a random JWT secret" >&2
    return 1
  fi

  (umask 077; printf '%s\n' "$generated" > "$secret_file")
  chmod 600 "$secret_file"
  printf '%s' "$generated"
}
