-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: DeleteHostServicesStaleBatched :execrows
-- Retention sweep (batched) for host_services. host_services is upserted on
-- (ip, service, port), so it does not append per-scan, but rows for hosts
-- that have gone silent are never refreshed and linger. This removes rows
-- whose updated_at is older than the cutoff, in batches to avoid holding the
-- write lock on large tables (mirrors the other retention deletes).
DELETE FROM host_services
WHERE id IN (
    SELECT sub.id FROM host_services AS sub WHERE sub.updated_at < ? LIMIT ?
);

-- name: InsertHostService :exec
-- One classified service-identity row (scannerv2/store RecordServices,
-- #269: the insert half moved to sqlc; the scoped DELETE with its DYNAMIC
-- port IN-list stays raw in the store, sqlc cannot bind a slice to IN).
-- Plain INSERT: the scoped DELETE runs first in the same tx so conflicts
-- cannot occur; an upsert form trips sqlc's SQLite parser on the
-- unique-INDEX conflict target. updated_at is RFC3339 text (DBTime).
INSERT INTO host_services (ip, device_uuid, service, port, protocol, confidence, metadata, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS TEXT));
