package domain

import "time"

// DocumentType represents the type of a document.
type DocumentType string

const (
	DocTypeURL  DocumentType = "url"
	DocTypeFile DocumentType = "file"
)

// Request types

type CreateDocumentRequest struct {
	Title       string `json:"title"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

type UpdateDocumentRequest struct {
	Title       *string `json:"title,omitempty"`
	URL         *string `json:"url,omitempty"`
	Description *string `json:"description,omitempty"`
}

// Response types

type DocumentResponse struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Type        string    `json:"type"`
	URL         string    `json:"url"`
	FilePath    string    `json:"file_path"`
	FileSize    int64     `json:"file_size"`
	MimeType    string    `json:"mime_type"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type DocumentListResponse struct {
	Documents []DocumentResponse `json:"documents"`
	Total     int                `json:"total"`
}
