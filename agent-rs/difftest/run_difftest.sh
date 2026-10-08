#!/usr/bin/env bash
# Differential test runner: Go oracle vs Rust oracle over the same battery.
# Usage: bash difftest/run_difftest.sh [corpus_dir]
set -uo pipefail
cd "$(dirname "$0")/.."

# corpus default: nested-in-main-repo layout first, then sibling checkout
if [ -d ../../configs/fingerprints ]; then
  CORPUS="${1:-../../configs/fingerprints}"
else
  CORPUS="${1:-../MiBeeSteward/configs/fingerprints}"
fi
CORPUS_ABS=$(cd "$CORPUS" && pwd | sed 's|^/d/|D:/|;s|^/c/|C:/|')
BATT=difftest/battery.jsonl

python difftest/gen_battery.py "$CORPUS_ABS" "$BATT" 20261005 || exit 1

GOBIN=../mibee-fingerprints-go/tmp/oracle/oracle.exe
if [ ! -x "$GOBIN" ]; then
  echo "go oracle missing; build it first (see difftest/go_oracle_main.go)"; exit 1
fi
"$GOBIN" < "$BATT" > difftest/out_go.jsonl 2> difftest/err_go.txt || true
cargo run -q --release -p mibee-fingerprints --example oracle < "$BATT" > difftest/out_rs.jsonl 2> difftest/err_rs.txt || true

echo "go lines: $(wc -l < difftest/out_go.jsonl)  rust lines: $(wc -l < difftest/out_rs.jsonl)"
if [ -s difftest/err_go.txt ]; then echo "-- go stderr --"; head -3 difftest/err_go.txt; fi
if [ -s difftest/err_rs.txt ]; then echo "-- rust stderr --"; head -3 difftest/err_rs.txt; fi

# Byte-for-byte compare; on mismatch show first differing line pair.
if cmp -s difftest/out_go.jsonl difftest/out_rs.jsonl; then
  echo "DIFFTEST: PASS (byte-identical)"
  exit 0
fi
echo "DIFFTEST: FAIL — first differences:"
go_iter=1
paste -d'\n' /dev/null /dev/null 2>/dev/null || true
python - << 'EOF'
import json
go = open('difftest/out_go.jsonl', encoding='utf8').read().splitlines()
rs = open('difftest/out_rs.jsonl', encoding='utf8').read().splitlines()
n = 0
for i, (g, r) in enumerate(zip(go, rs)):
    if g != r:
        n += 1
        if n <= 5:
            print(f'== line {i+1} differs ==')
            print('GO:', g[:400])
            print('RS:', r[:400])
            try:
                gj, rj = json.loads(g), json.loads(r)
                gi, ri = gj['identities'], rj['identities']
                print(f'   counts go={len(gi)} rs={len(ri)}')
                for a, b in zip(gi, ri):
                    if a != b:
                        print('   GO id :', json.dumps(a)[:240])
                        print('   RS id :', json.dumps(b)[:240])
                        break
            except Exception as e:
                print('   parse:', e)
if n == 0 and len(go) != len(rs):
    print(f'line counts differ: go={len(go)} rs={len(rs)}')
print(f'total differing lines: {n}')
EOF
exit 1
