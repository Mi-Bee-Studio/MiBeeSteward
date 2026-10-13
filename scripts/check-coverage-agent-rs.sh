#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
#
# This file is part of MiBee Steward, distributed under the GNU Affero General
# Public License v3.0 or later. See LICENSE for the full text. A commercial
# license is available for use cases the AGPL does not accommodate; see
# LICENSE-COMMERCIAL.md.

# agent-rs: line-coverage ratchet gate (the Rust mirror of check-coverage.sh).
# Usage: scripts/check-coverage-agent-rs.sh [lcov-path]
#   (default: agent-rs/lcov.info, produced by `make coverage-agent-rs`)
#
# Fails when total line coverage of the cargo workspace drops below the floor
# recorded in agent-rs/coverage-floor.txt. The floor only ever moves UP:
# after adding tests, run `make coverage-agent-rs-bump` to re-pin it; lowering
# the floor means editing the file by hand (deliberately frictional).
#
# Line coverage (not region/branch) is the metric: it is the closest analog of
# the Go side's statement coverage and the number agent-rs.md quotes. The lcov
# LF/LH sums are computed from the per-file summary records, so the script is
# immune to cargo-llvm-cov's text-table column reshuffles.

set -euo pipefail

lcov="${1:-agent-rs/lcov.info}"
floor_file="$(cd "$(dirname "$0")/.." && pwd)/agent-rs/coverage-floor.txt"

if [[ ! -f "$lcov" ]]; then
  echo "lcov profile '$lcov' not found: run 'make coverage-agent-rs' first" >&2
  exit 1
fi

floor=$(tr -d '[:space:]' < "$floor_file")
if ! grep -Eq '^[0-9]+(\.[0-9]+)?$' <<< "$floor"; then
  echo "invalid floor '$floor' in $floor_file (expected a number like 73.0)" >&2
  exit 1
fi

total=$(awk -F: '/^LF:/ {found += $2} /^LH:/ {hit += $2} END {if (found > 0) printf "%.1f", 100 * hit / found; else print "0"}' "$lcov")

echo "agent-rs line coverage: ${total}%  (floor: ${floor}%)"
if awk -v t="$total" -v f="$floor" 'BEGIN { exit (t + 0 < f + 0) ? 1 : 0 }'; then
  echo "OK: coverage is at or above the floor"
else
  echo "::error::agent-rs line coverage ${total}% fell below the ratchet floor ${floor}%" >&2
  echo "Add tests to restore coverage, or (if you added tests) re-pin with 'make coverage-agent-rs-bump'. Never lower the floor to pass." >&2
  exit 1
fi
