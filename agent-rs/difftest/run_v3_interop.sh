#!/usr/bin/env bash
# SNMPv3 USM interop difftest: gosnmp (the library the Go agent uses)
# client against the Rust v3_echo_agent. Every auth × priv family gets a
# full exchange: engine discovery, HMAC verification both directions,
# AES-CFB128/DES-CBC both directions. Requires go + cargo on PATH; gosnmp
# resolves from the local module cache (GOPROXY=off).
set -u
cd "$(dirname "$0")/.."

PORT="${V3_INTEROP_PORT:-18961}"
COMBOS=(
  "noAuthNoPriv NoAuth NoPriv"
  "authNoPriv MD5 NoPriv"
  "authNoPriv SHA NoPriv"
  "authNoPriv SHA512 NoPriv"
  "authPriv SHA DES"
  "authPriv MD5 AES"
  "authPriv SHA224 AES"
  "authPriv SHA384 AES192"
  "authPriv SHA512 AES256"
  "authPriv SHA256 AES192C"
  "authPriv SHA256 AES256C"
)

echo "== building rust echo agent + go client =="
cargo build -q -p mibee-agent --example v3_echo_agent || exit 1
AGENT="target/debug/examples/v3_echo_agent"

(cd difftest/v3client && GOFLAGS=-mod=mod GOPROXY=off go build -o v3client.exe .) || exit 1
CLIENT="difftest/v3client/v3client.exe"

pass=0; fail=0
for combo in "${COMBOS[@]}"; do
  set -- $combo
  level="$1"; auth="$2"; priv="$3"
  "$AGENT" "$PORT" "$level" "$auth" "$priv" 2>/dev/null &
  agent_pid=$!
  # wait for the port
  for _ in $(seq 1 50); do
    if netstat -an | grep -q "127.0.0.1:$PORT .*LISTEN"; then break; fi
    sleep 0.1
  done
  out="$("$CLIENT" "$PORT" "$auth" "$priv" 2>&1)"
  kill $agent_pid 2>/dev/null; wait $agent_pid 2>/dev/null
  if [[ "$out" == OK* ]]; then
    echo "PASS  $level/$auth/$priv -> $out"
    pass=$((pass+1))
  else
    echo "FAIL  $level/$auth/$priv -> $out"
    fail=$((fail+1))
  fi
  sleep 0.2
done
echo "== v3 interop: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
