#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (c) 2026 MiBee Studio. All rights reserved.
#
# This file is part of MiBee Steward, distributed under the GNU Affero General
# Public License v3.0 or later. You use, modify, and redistribute it under
# those terms; see LICENSE for the full text. A commercial license is available
# for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

# MiBee Steward — statement-coverage ratchet gate.
# Usage: scripts/check-coverage.sh [profile]   (default: cover.out in repo root)
#
# Fails when total statement coverage of the measured package set drops below
# the floor recorded in scripts/coverage-floor.txt. The floor only ever moves
# UP: after adding tests, run `make coverage-bump` to re-pin it to the new
# level; lowering the floor requires editing the file by hand (deliberately
# frictional).
#
# The measured set EXCLUDES generated/dev-only code that has its own drift
# gates instead: internal/db (sqlc — sqlc-verify job), internal/apiclient
# (oapi-codegen — gen-api-go drift check), cmd/loadgen (dev-only load tool).
# The profile must be produced by `make coverage` (which passes -coverpkg) —
# a plain `go test -coverprofile` undercounts because it only attributes
# coverage to a package's own tests.

set -euo pipefail

profile="${1:-cover.out}"
floor_file="$(cd "$(dirname "$0")" && pwd)/coverage-floor.txt"

if [[ ! -f "$profile" ]]; then
  echo "coverage profile '$profile' not found — run 'make coverage' first" >&2
  exit 1
fi

floor=$(tr -d '[:space:]' < "$floor_file")
if ! grep -Eq '^[0-9]+(\.[0-9]+)?$' <<< "$floor"; then
  echo "invalid floor '$floor' in $floor_file (expected a number like 63.0)" >&2
  exit 1
fi

total=$(go tool cover -func="$profile" | awk '/^total:/ {sub(/%/, "", $NF); print $NF}')

echo "statement coverage: ${total}%  (floor: ${floor}%)"
if awk -v t="$total" -v f="$floor" 'BEGIN { exit (t + 0 < f + 0) ? 1 : 0 }'; then
  echo "OK — coverage is at or above the floor"
else
  echo "::error::statement coverage ${total}% fell below the ratchet floor ${floor}%" >&2
  echo "Add tests to restore coverage, or (if you added tests) re-pin with 'make coverage-bump'. Never lower the floor to pass." >&2
  exit 1
fi
