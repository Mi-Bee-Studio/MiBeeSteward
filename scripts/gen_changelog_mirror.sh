#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regenerate the docs/{zh,en}/changelog.md mirrors from the root CHANGELOG.md
# (#322). Run via `make docs-changelog-sync` whenever CHANGELOG.md changes; the
# CI `docs` job runs this same script and fails on drift, so a release that
# forgets to refresh the mirrors is caught before merge.
#
# - en/changelog.md: verbatim copy of CHANGELOG.md
# - zh/changelog.md: one-line Chinese provenance note + the verbatim content
#
# Do not hand-edit the mirrors — edit CHANGELOG.md and re-run this script.

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f CHANGELOG.md ]]; then
  echo "error: CHANGELOG.md not found at repo root" >&2
  exit 1
fi

cp CHANGELOG.md docs/en/changelog.md

{
  echo "> 本页由 \`make docs-changelog-sync\` 从仓库根目录 [CHANGELOG.md](../../CHANGELOG.md) 自动生成（保留英文原文，便于与仓库逐字对照），请勿手改。"
  echo
  echo
  cat CHANGELOG.md
} > docs/zh/changelog.md

echo "docs/{zh,en}/changelog.md regenerated from CHANGELOG.md"
