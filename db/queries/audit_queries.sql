-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: ListAuditLogs :many
SELECT id, user_id, action, resource_type, resource_id, ip_address, user_agent, details, created_at
FROM audit_logs
WHERE (? = 0 OR user_id = ?)
  AND (? = '' OR action = ?)
  AND (? = '' OR resource_type = ?)
  AND (? = '' OR created_at >= ?)
  AND (? = '' OR created_at <= ?)
  AND (? = '' OR INSTR(lower(action), lower(?)) > 0 OR INSTR(lower(resource_type), lower(?)) > 0 OR INSTR(lower(ip_address), lower(?)) > 0)
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: CountAuditLogs :one
SELECT COUNT(*) FROM audit_logs
WHERE (? = 0 OR user_id = ?)
  AND (? = '' OR action = ?)
  AND (? = '' OR resource_type = ?)
  AND (? = '' OR created_at >= ?)
  AND (? = '' OR created_at <= ?)
  AND (? = '' OR INSTR(lower(action), lower(?)) > 0 OR INSTR(lower(resource_type), lower(?)) > 0 OR INSTR(lower(ip_address), lower(?)) > 0);

-- name: DistinctAuditActions :many
-- Facets for the audit page filter dropdowns. Distinct values are pulled
-- straight from the table (rather than a hardcoded list in the frontend) so a
-- new action emitted by the backend shows up automatically. idx_audit_logs_action
-- makes the DISTINCT scan cheap; resource_type is unindexed but the table is
-- retention-bounded (90d default) so the scan is bounded too.
SELECT DISTINCT action FROM audit_logs ORDER BY action;

-- name: DistinctAuditResourceTypes :many
SELECT DISTINCT resource_type FROM audit_logs ORDER BY resource_type;

-- name: DeleteAuditLogsOlderThan :execrows
-- Retention sweep: prune audit rows older than the cutoff. Batched deletion is
-- done in Go (DELETE rowid IN (SELECT ... LIMIT ?)) to avoid a single giant
-- transaction; this plain form is kept for small/fallback use.
DELETE FROM audit_logs WHERE created_at < ?;

-- name: DeleteAuditLogsOlderThanBatched :execrows
-- Batched form: deletes up to ? rows (by rowid) older than the cutoff. The
-- sweeper loops this until the affected-row count drops below the batch size.
DELETE FROM audit_logs
WHERE rowid IN (
    SELECT rowid FROM audit_logs WHERE audit_logs.created_at < ? LIMIT ?
);
