#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
#
# This file is part of MiBee Steward, distributed under the GNU Affero General
# Public License v3.0 or later. You may use, modify, and redistribute it under
# those terms; see LICENSE for the full text. A commercial license is available
# for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

# MiBee Steward — SQLite Backup Script
# Usage: ./scripts/backup.sh [DB_PATH] [BACKUP_DIR] [RETENTION_DAYS]
# Cron example: 0 2 * * * /opt/mibee-steward/scripts/backup.sh

set -euo pipefail

DB_PATH="${1:-./data/mibee.db}"
BACKUP_DIR="${2:-./data/backups}"
RETENTION_DAYS="${3:-7}"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Generate timestamp-based filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/mibee-${TIMESTAMP}.db"

# Check database file exists
if [ ! -f "$DB_PATH" ]; then
    echo "ERROR: Database file not found: $DB_PATH" >&2
    exit 1
fi

# Perform safe backup using sqlite3 .backup command
# This does NOT lock the database — safe for production use
echo "Backing up ${DB_PATH} to ${BACKUP_FILE}..."
sqlite3 "$DB_PATH" ".backup '${BACKUP_FILE}'"

# Verify backup integrity
if sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" | grep -q "ok"; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "Backup completed successfully: ${BACKUP_FILE} (${SIZE})"
else
    echo "ERROR: Backup integrity check failed: ${BACKUP_FILE}" >&2
    rm -f "$BACKUP_FILE"
    exit 1
fi

# Remove backups older than RETENTION_DAYS
DELETED=$(find "$BACKUP_DIR" -name "mibee-*.db" -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
if [ "$DELETED" -gt 0 ]; then
    echo "Removed ${DELETED} old backup(s) (older than ${RETENTION_DAYS} days)"
fi
