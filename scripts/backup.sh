#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (c) 2026 Mi Bee Studio. All rights reserved.
#
# This file is part of MiBee Steward, distributed under the GNU Affero
# General Public License v3.0 or later. See the LICENSE file for the full
# text. A commercial license is available for use cases the AGPL does not
# accommodate; see LICENSE-COMMERCIAL.md.

# Compatibility wrapper for the built-in, zero-external-dependency backup
# command. The old script required sqlite3 and backed up only mibee.db; the
# binary now snapshots every top-level SQLite file plus uploads, fingerprints,
# instance identity and config into a verified bundle.
#
# Usage: ./backup.sh [DB_PATH] [BACKUP_DIR] [RETENTION_DAYS]
# Cron example: 0 2 * * * /opt/mibee-steward/scripts/backup.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${1:-./data/mibee.db}"
BACKUP_DIR="${2:-./data/backups}"
RETENTION_DAYS="${3:-7}"

if [ -n "${MIBEE_BIN:-}" ]; then
  BIN="$MIBEE_BIN"
elif [ -x "$ROOT/mibee-steward" ]; then
  BIN="$ROOT/mibee-steward"
elif [ -x "$ROOT/../mibee-steward" ]; then
  BIN="$ROOT/../mibee-steward"
elif [ -x "$ROOT/../bin/mibee-steward" ]; then
  BIN="$ROOT/../bin/mibee-steward"
else
  echo "ERROR: mibee-steward binary not found; set MIBEE_BIN" >&2
  exit 1
fi

if [ -n "${MIBEE_CONFIG:-}" ]; then
  CONFIG="$MIBEE_CONFIG"
elif [ -f "$ROOT/configs/config.yaml" ]; then
  CONFIG="$ROOT/configs/config.yaml"
elif [ -f "$ROOT/../configs/config.yaml" ]; then
  CONFIG="$ROOT/../configs/config.yaml"
else
  echo "ERROR: config.yaml not found; set MIBEE_CONFIG" >&2
  exit 1
fi

exec "$BIN" backup \
  -config "$CONFIG" \
  -db "$DB_PATH" \
  -output "$BACKUP_DIR" \
  -retention-days "$RETENTION_DAYS"
