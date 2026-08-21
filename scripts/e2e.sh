#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
#
# This file is part of MiBee Steward, distributed under the GNU Affero General
# Public License v3.0 or later. You can use, copy, modify, and redistribute it
# under those terms; see LICENSE for the full text. A commercial license is
# available for use cases the AGPL does not accommodate; see
# LICENSE-COMMERCIAL.md.

# MiBee Steward end-to-end smoke test (#270).
#
# Black-box: builds the center, runs it against a throwaway data dir, then
# asserts the four regression classes unit tests struggle to catch:
#   1. agent-reported devices land in the inventory (report ingest + bridge)
#   2. a live service is discovered and classified (scan → host_services)
#   3. a rescan REFRESHES results instead of silently freezing (#253 class:
#      async task triggered twice → one upserted row with a newer scanned_at)
#   4. probe-target results persist (probe engine → probe_results, the path
#      that lost ~12% of writes to SQLITE_BUSY, #252 class)
# plus /health and /metrics availability.
#
# The scan target is the center itself (loopback: its HTTP port is a real
# service), so no external listener or python is needed. Runtime < 60s.
#
# Usage: ./scripts/e2e.sh          (from the repo root)
# Requires: go, curl. Exits non-zero on the first failed assertion.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
PORT="${E2E_PORT:-18099}"
BASE="http://127.0.0.1:${PORT}"
BIN="${TMP}/mibee-steward"
PASS=0
FAIL=0

cleanup() {
    [ -n "${SERVER_PID:-}" ] && kill "${SERVER_PID}" 2>/dev/null || true
    rm -rf "${TMP}"
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
need() { if [ "$1" != "$2" ]; then bad "$3 (got: $1, want: $2)"; else ok "$3"; fi }

jsonget() { # jsonget <json> <key> — crude extractor for scalar string/number fields
    printf '%s' "$1" | grep -o "\"$2\":[^,}]*" | head -1 | cut -d: -f2- | tr -d '"'
}

echo "== e2e smoke (#270) — building center =="
(cd "${ROOT}" && CGO_ENABLED=0 go build -o "${BIN}" ./cmd/server/) || { echo "build failed"; exit 1; }

echo "== starting center on :${PORT} =="
mkdir -p "${TMP}/data"
cat > "${TMP}/config.yaml" <<EOF
server:
  port: ${PORT}
database:
  sqlite:
    path: "${TMP}/data/mibee.db"
auth:
  initial_admin_password: "e2e-Admin-2026"
  jwt_secret: "e2e-jwt-secret-only-for-smoke-test-0123456789"
log:
  level: "warn"
EOF
"${BIN}" -config "${TMP}/config.yaml" > "${TMP}/server.log" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 50); do
    curl -sf -m 2 "${BASE}/api/v1/health" >/dev/null 2>&1 && break
    sleep 0.2
done

echo "== 1. health & metrics =="
HEALTH="$(curl -sf -m 3 "${BASE}/api/v1/health" || echo '')"
need "$(jsonget "${HEALTH}" status)" "ok" "GET /health returns ok"
METRICS="$(curl -sf -m 3 "${BASE}/metrics" || echo '')"
if printf '%s' "${METRICS}" | grep -q "mibee_api_requests_total"; then
    ok "GET /metrics exposes mibee_ metric families"
else
    bad "GET /metrics missing mibee_ metrics"
fi

echo "== login =="
LOGIN="$(curl -sf -m 5 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"e2e-Admin-2026"}')"
TOKEN="$(jsonget "${LOGIN}" token)"
[ -n "${TOKEN}" ] && ok "admin login issued a token" || bad "login failed"

echo "== 2. agent report → inventory =="
NET="$(curl -sf -m 5 -X POST "${BASE}/api/v1/networks" \
    -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    -d '{"name":"e2e-lan","cidr":"10.99.0.0/24"}')"
NET_ID="$(jsonget "${NET}" id)"
[ -n "${NET_ID}" ] && ok "network created (id=${NET_ID})" || bad "network create failed"

TOKRES="$(curl -sf -m 5 -X POST "${BASE}/api/v1/agents/tokens" \
    -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"agent_id\":\"e2e-agent\",\"network_id\":${NET_ID},\"name\":\"e2e\"}")"
AGTOK="$(jsonget "${TOKRES}" token)"
[ -n "${AGTOK}" ] && ok "agent token minted" || bad "agent token create failed"

REPORT='{"agent_id":"e2e-agent","network_cidr":"10.99.0.0/24","scanned_at":"2026-01-01T00:00:00Z","hosts":[
  {"ip":"10.99.0.11","alive":true,"mac":"02:11:aa:bb:cc:01","inferred_type":"camera","inferred_brand":"TestCam"},
  {"ip":"10.99.0.12","alive":true,"mac":"02:11:aa:bb:cc:02","inferred_type":"pc"}]}'
ACK="$(curl -sf -m 5 -X POST "${BASE}/api/v1/agents/report" \
    -H "Authorization: Bearer ${AGTOK}" -H 'Content-Type: application/json' -d "${REPORT}" || echo '')"
need "$(jsonget "${ACK}" accepted)" "2" "agent report accepted (2 hosts)"

DEVLIST="$(curl -sf -m 5 "${BASE}/api/v1/devices?search=10.99.0.11" -H "Authorization: Bearer ${TOKEN}" || echo '{}')"
if printf '%s' "${DEVLIST}" | grep -q "10.99.0.11"; then
    ok "agent-reported device 10.99.0.11 landed in inventory"
else
    bad "agent-reported device missing from inventory"
fi

echo "== 3. live-service discovery (scan the center itself) =="
SCAN="$(curl -sf -m 60 -X POST "${BASE}/api/v1/scanner/scan" \
    -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"targets\":\"127.0.0.1\",\"community\":\"public\",\"timeout\":10,\"ports\":\"${PORT}\"}" || echo '{}')"
if printf '%s' "${SCAN}" | grep -q '"alive":true'; then
    ok "sync scan found 127.0.0.1 alive"
else
    bad "sync scan did not find the center itself alive"
fi
# The sync path lands in the device portrait: open_ports must carry the
# center's own HTTP port (scan_results is the ASYNC-task store, asserted
# in section 4).
# open_ports is an escaped-JSON string ([{\"port\":N,...}]) — grep the raw
# response for the port entry rather than extracting the string.
DEVJSON="$(curl -sf -m 5 "${BASE}/api/v1/devices?search=127.0.0.1" -H "Authorization: Bearer ${TOKEN}" || echo '')"
if printf '%s' "${DEVJSON}" | grep -q "\\\"port\\\":${PORT}"; then
    ok "device portrait carries open port ${PORT} (live-service discovery)"
else
    bad "device portrait missing open port ${PORT}"
fi

echo "== 4. rescan refreshes (anti-#253) =="
TASK="$(curl -sf -m 5 -X POST "${BASE}/api/v1/scanner/tasks" \
    -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    -d '{"name":"e2e-task","targets":"127.0.0.1","cron_expr":"0 3 1 1 *","timeout":30,"concurrent_hosts":8,"pipeline_config":{"icmp":{"enabled":true},"snmp":{"enabled":false},"port_scan":{"enabled":true,"ports":"22,80,443,8080"},"service_detect":{"enabled":true}}}')"
TASK_ID="$(jsonget "${TASK}" id)"
[ -n "${TASK_ID}" ] && ok "async task created (id=${TASK_ID})" || bad "task create failed"
curl -sf -m 5 -X POST "${BASE}/api/v1/scanner/tasks/${TASK_ID}/trigger" -H "Authorization: Bearer ${TOKEN}" >/dev/null
for i in $(seq 1 60); do
    RUNS="$(curl -sf -m 5 "${BASE}/api/v1/scanner/tasks/${TASK_ID}/runs?limit=1" -H "Authorization: Bearer ${TOKEN}")"
    printf '%s' "${RUNS}" | grep -q '"status":"completed"' && break
    sleep 1
done
RES1="$(curl -sf -m 5 "${BASE}/api/v1/scanner/results?task_id=${TASK_ID}" -H "Authorization: Bearer ${TOKEN}")"
AT1="$(printf '%s' "${RES1}" | grep -o '"scanned_at":"[^"]*"' | head -1)"
sleep 2
curl -sf -m 5 -X POST "${BASE}/api/v1/scanner/tasks/${TASK_ID}/trigger" -H "Authorization: Bearer ${TOKEN}" >/dev/null
sleep 6   # let the second run complete and upsert
RES2="$(curl -sf -m 5 "${BASE}/api/v1/scanner/results?task_id=${TASK_ID}" -H "Authorization: Bearer ${TOKEN}")"
AT2="$(printf '%s' "${RES2}" | grep -o '"scanned_at":"[^"]*"' | head -1)"
ROWS="$(printf '%s' "${RES2}" | grep -o '"ip": *"127.0.0.1"' | wc -l | tr -d ' ')"
need "${ROWS}" "1" "rescan kept ONE result row (upsert, not duplicate)"
if [ "${AT1}" != "${AT2}" ] && [ -n "${AT2}" ]; then
    ok "rescan refreshed scanned_at (${AT1} → ${AT2})"
else
    bad "rescan did not refresh scanned_at (#253 regression class)"
fi

echo "== 5. probe-target persistence (anti-#252) =="
curl -sf -m 5 -X POST "${BASE}/api/v1/probe-targets" \
    -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"e2e-self\",\"module\":\"http\",\"target\":\"${BASE}/api/v1/health\",\"interval_seconds\":10,\"timeout_seconds\":5}" >/dev/null
PSTAT=1
for i in $(seq 1 20); do
    PLIST="$(curl -sf -m 5 "${BASE}/api/v1/probe-targets" -H "Authorization: Bearer ${TOKEN}" || echo '{}')"
    PID="$(printf '%s' "${PLIST}" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)"
    [ -n "${PID}" ] && break
    sleep 1
done
PRES=""
for i in $(seq 1 20); do
    PRES="$(curl -sf -m 5 "${BASE}/api/v1/probe-targets/${PID}/results?limit=1" -H "Authorization: Bearer ${TOKEN}" || echo '')"
    printf '%s' "${PRES}" | grep -q '"status":"success"' && break
    sleep 2
done
if printf '%s' "${PRES}" | grep -q '"status":"success"'; then
    ok "probe-target result persisted (http ${BASE}/api/v1/health)"
else
    bad "probe-target produced no persisted result (#252 regression class)"
fi

echo
echo "== e2e result: ${PASS} passed, ${FAIL} failed — log: ${TMP}/server.log =="
[ "${FAIL}" -eq 0 ] || { echo "server log tail:"; tail -20 "${TMP}/server.log" || true; exit 1; }
