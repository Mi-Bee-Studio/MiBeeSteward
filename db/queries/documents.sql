-- name: CreateDocument :one
INSERT INTO documents (title, type, url, file_path, file_size, mime_type, description)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at;

-- name: GetDocument :one
SELECT id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at
FROM documents
WHERE id = ?;

-- name: ListDocuments :many
SELECT id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at
FROM documents
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpdateDocument :one
UPDATE documents
SET title = ?, type = ?, url = ?, file_path = ?, file_size = ?, mime_type = ?, description = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, title, type, url, file_path, file_size, mime_type, description, created_at, updated_at;

-- name: DeleteDocument :execrows
DELETE FROM documents
WHERE id = ?;
