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
RETURNING id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at;

-- name: GetDocument :one
SELECT id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at
FROM documents
WHERE id = ?;

-- name: ListDocuments :many
-- Search is a substring match across title/description/type (case-insensitive).
-- INSTR pattern (see ListUsers for rationale).
SELECT id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at
FROM documents
WHERE (? = '' OR INSTR(lower(title), lower(?)) > 0 OR INSTR(lower(description), lower(?)) > 0 OR INSTR(lower(type), lower(?)) > 0)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: CountDocuments :one
-- Mirrors ListDocuments WHERE so the page total reflects the active search.
SELECT COUNT(*) FROM documents
WHERE (? = '' OR INSTR(lower(title), lower(?)) > 0 OR INSTR(lower(description), lower(?)) > 0 OR INSTR(lower(type), lower(?)) > 0);

-- name: UpdateDocument :one
UPDATE documents
SET title = ?, type = ?, url = ?, file_path = ?, file_size = ?, mime_type = ?, description = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at;

-- name: DeleteDocument :execrows
DELETE FROM documents
WHERE id = ?;
