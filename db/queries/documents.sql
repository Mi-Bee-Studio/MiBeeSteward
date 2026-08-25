-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateDocument :one
INSERT INTO documents (title, type, url, file_path, file_size, mime_type, description)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, title, type, url, file_path, file_size, mime_type, description, deleted_at, created_at, updated_at;

-- name: GetDocument :one
SELECT id, title, type, url, file_path, file_size, mime_type, description, deleted_at, created_at, updated_at
FROM documents
WHERE id = ? AND deleted_at IS NULL;

-- name: ListDocuments :many
-- Search is a substring match across title/description/type (case-insensitive).
-- INSTR pattern (see ListUsers for rationale).
SELECT id, title, type, url, file_path, file_size, mime_type, description, deleted_at, created_at, updated_at
FROM documents
WHERE deleted_at IS NULL AND (? = '' OR INSTR(lower(title), lower(?)) > 0 OR INSTR(lower(description), lower(?)) > 0 OR INSTR(lower(type), lower(?)) > 0)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountDocuments :one
-- Mirrors ListDocuments WHERE so the page total reflects the active search.
SELECT COUNT(*) FROM documents
WHERE deleted_at IS NULL AND (? = '' OR INSTR(lower(title), lower(?)) > 0 OR INSTR(lower(description), lower(?)) > 0 OR INSTR(lower(type), lower(?)) > 0);

-- name: UpdateDocument :one
UPDATE documents
SET title = ?, type = ?, url = ?, file_path = ?, file_size = ?, mime_type = ?, description = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND deleted_at IS NULL
RETURNING id, title, type, url, file_path, file_size, mime_type, description, deleted_at, created_at, updated_at;

-- name: DeleteDocument :execrows
-- Soft delete: stamp the tombstone, keep the row (and its file on disk) so
-- POST /documents/{id}/restore can undo. Physical purge is a later concern.
UPDATE documents
SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND deleted_at IS NULL;

-- name: RestoreDocument :execrows
-- Undo a soft delete (the UI's delete-undo toast). Only clears the tombstone.
UPDATE documents
SET deleted_at = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND deleted_at IS NOT NULL;
