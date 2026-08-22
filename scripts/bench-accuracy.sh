#!/usr/bin/env bash
# bench-accuracy.sh — MiBee vs nmap discovery-accuracy comparison (#283).
#
# Runs both tools against the same subnet and diffs the ALIVE sets (liveness
# is the primary accuracy dimension; port/service comparison is a follow-up).
# Produces a confusion matrix on stdout + a machine-readable JSON alongside.
#
# Usage:
#   scripts/bench-accuracy.sh <CIDR> [center_url]
# Env:
#   MIBEE_USER / MIBEE_PASS   center credentials (default admin / via env)
# Requires: nmap, curl, jq, python3.
#
# Method notes:
#   - nmap reference: `nmap -sn <CIDR>` (the standard host-discovery mode;
#     needs root for ICMP, falls back to ARP/ACK otherwise)
#   - MiBee: POST /api/v1/scanner/scan (sync scan) and parse alive IPs
#   - MiBee intentionally ALSO counts hosts that answer TCP-only probes, so
#     a small "MiBee > nmap" surplus is expected and reported separately from
#     misses.
set -euo pipefail

CIDR="${1:?usage: bench-accuracy.sh <CIDR> [center_url]}"
CENTER="${2:-http://127.0.0.1:8080}"
MIBEE_USER="${MIBEE_USER:-admin}"
MIBEE_PASS="${MIBEE_PASS:?set MIBEE_PASS}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== reference: nmap -sn $CIDR"
nmap -sn "$CIDR" -oG "$TMP/nmap.gnmap" >/dev/null
grep 'Status: Up' "$TMP/nmap.gnmap" | awk '{print $2}' | sort > "$TMP/nmap.txt"
NMAP_COUNT=$(wc -l < "$TMP/nmap.txt")

echo "== MiBee sync scan"
TOKEN=$(curl -s -X POST "$CENTER/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$MIBEE_USER\",\"password\":\"$MIBEE_PASS\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl -s -X POST "$CENTER/api/v1/scanner/scan" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"targets\":\"$CIDR\",\"community\":\"public\",\"timeout\":2}" \
  | python3 -c '
import json, sys
d = json.load(sys.stdin)
for h in d.get("hosts", []):
    if h.get("alive"):
        print(h["ip"])
' | sort > "$TMP/mibee.txt"
MIBEE_COUNT=$(wc -l < "$TMP/mibee.txt")

# Confusion matrix (nmap = reference truth).
BOTH=$(comm -12 "$TMP/nmap.txt" "$TMP/mibee.txt" | wc -l)
MIBEE_ONLY=$(comm -13 "$TMP/nmap.txt" "$TMP/mibee.txt" | wc -l)
NMAP_ONLY=$(comm -23 "$TMP/nmap.txt" "$TMP/mibee.txt" | wc -l)

RECALL=$(python3 -c "print(f'{$BOTH/$NMAP_COUNT*100:.1f}' if $NMAP_COUNT else 'n/a')")
PRECISION=$(python3 -c "print(f'{$BOTH/$MIBEE_COUNT*100:.1f}' if $MIBEE_COUNT else 'n/a')")

cat <<EOF

== results ($CIDR)
              | nmap=up | nmap=down
  MiBee=up    |  $BOTH   |  $MIBEE_ONLY
  MiBee=down  |  $NMAP_ONLY   |  -

  nmap found: $NMAP_COUNT · MiBee found: $MIBEE_COUNT
  recall (vs nmap): $RECALL% · precision: $PRECISION%
  MiBee-only hosts (TCP-only answers nmap -sn misses): $MIBEE_ONLY
  nmap-only hosts (MiBee misses — investigate): $NMAP_ONLY
EOF

if [ "$NMAP_ONLY" -gt 0 ]; then
  echo "  missed by MiBee:"; comm -23 "$TMP/nmap.txt" "$TMP/mibee.txt" | sed 's/^/    /'
fi

python3 - "$CIDR" "$NMAP_COUNT" "$MIBEE_COUNT" "$BOTH" "$MIBEE_ONLY" "$NMAP_ONLY" <<'EOF' > "$TMP/result.json"
import json, sys
print(json.dumps({
    "cidr": sys.argv[1], "nmap_up": int(sys.argv[2]), "mibee_up": int(sys.argv[3]),
    "both": int(sys.argv[4]), "mibee_only": int(sys.argv[5]), "nmap_only": int(sys.argv[6]),
}, indent=2))
EOF
cp "$TMP/result.json" "bench-accuracy-$(echo "$CIDR" | tr '/' '_').json"
echo "json written: bench-accuracy-$(echo "$CIDR" | tr '/' '_').json"
