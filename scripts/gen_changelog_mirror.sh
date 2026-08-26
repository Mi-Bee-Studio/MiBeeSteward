#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Changelog docs sync (#322, reworked 2026-08): docs/en/changelog.md is a
# verbatim mirror of the root CHANGELOG.md and is REGENERATED here. Do not
# hand-edit it — edit CHANGELOG.md and re-run `make docs-changelog-sync`.
#
# docs/zh/changelog.md is a hand-maintained CHINESE TRANSLATION — this script
# never touches it. Instead it runs a coverage check: the set of version
# headers (`## [Unreleased]` / `## [0.5.0] - date` / …) must be identical on
# both sides, so a release that adds entries to CHANGELOG.md without updating
# the translation (or vice versa) fails before merge.
#
# The CI `docs` job runs this same script and additionally fails when the
# regenerated en mirror differs from the committed one.

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f CHANGELOG.md ]]; then
  echo "error: CHANGELOG.md not found at repo root" >&2
  exit 1
fi
if [[ ! -f docs/zh/changelog.md ]]; then
  echo "error: docs/zh/changelog.md not found (hand-maintained translation)" >&2
  exit 1
fi

cp CHANGELOG.md docs/en/changelog.md

versions_of() {
  grep -E '^## \[' "$1" | grep -oE '\[[^]]+\]' | sort
}

if ! diff <(versions_of CHANGELOG.md) <(versions_of docs/zh/changelog.md) > /tmp/changelog-versions.diff; then
  echo "error: version coverage mismatch between CHANGELOG.md and docs/zh/changelog.md:" >&2
  cat /tmp/changelog-versions.diff >&2
  echo "Update the Chinese translation (docs/zh/changelog.md) to match, then re-run." >&2
  exit 1
fi

echo "docs/en/changelog.md regenerated from CHANGELOG.md; zh translation version coverage OK"
