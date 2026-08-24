// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"mime/multipart"
	"os"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

var (
	ErrDocumentNotFound = errors.New("document not found")
	ErrNotFileDocument  = errors.New("document is not a file type")
	ErrTitleRequired    = errors.New("title is required")
	ErrURLRequired      = errors.New("url is required")
)

// DocumentService handles document management business logic.
type DocumentService struct {
	queries *db.Queries
	upload  *UploadService
}

// NewDocumentService creates a new DocumentService.
func NewDocumentService(dbConn db.DBTX, uploadSvc *UploadService) *DocumentService {
	return &DocumentService{
		queries: db.New(dbConn),
		upload:  uploadSvc,
	}
}

// CreateURL creates a document with type="url".
func (s *DocumentService) CreateURL(ctx context.Context, req domain.CreateDocumentRequest) (*domain.DocumentResponse, error) {
	if req.Title == "" {
		return nil, ErrTitleRequired
	}
	if req.URL == "" {
		return nil, ErrURLRequired
	}

	doc, err := s.queries.CreateDocument(ctx, db.CreateDocumentParams{
		Title:       req.Title,
		Type:        string(domain.DocTypeURL),
		Url:         req.URL,
		Description: req.Description,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create document: %w", err)
	}

	resp := toDocumentResponse(doc)
	return &resp, nil
}

// UploadFile saves a file and creates a document with type="file".
func (s *DocumentService) UploadFile(ctx context.Context, file multipart.File, header *multipart.FileHeader, title string, description string) (*domain.DocumentResponse, error) {
	if title == "" {
		return nil, ErrTitleRequired
	}

	filePath, _, fileSize, mimeType, err := s.upload.SaveFile(file, header.Filename, header.Size)
	if err != nil {
		return nil, err
	}

	doc, err := s.queries.CreateDocument(ctx, db.CreateDocumentParams{
		Title:       title,
		Type:        string(domain.DocTypeFile),
		FilePath:    filePath,
		FileSize:    fileSize,
		MimeType:    mimeType,
		Description: description,
	})
	if err != nil {
		os.Remove(filePath)
		return nil, fmt.Errorf("failed to create document: %w", err)
	}

	resp := toDocumentResponse(doc)
	return &resp, nil
}

// Get retrieves a document by ID.
func (s *DocumentService) Get(ctx context.Context, id int64) (*domain.DocumentResponse, error) {
	doc, err := s.queries.GetDocument(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDocumentNotFound
		}
		return nil, fmt.Errorf("failed to get document: %w", err)
	}

	resp := toDocumentResponse(doc)
	return &resp, nil
}

// List returns documents with pagination.
func (s *DocumentService) List(ctx context.Context, search string, limit int64, offset int64) (*domain.DocumentListResponse, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	docs, err := s.queries.ListDocuments(ctx, db.ListDocumentsParams{
		Column1: search,
		LOWER:   search,
		LOWER_2: search,
		LOWER_3: search,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list documents: %w", err)
	}

	resp := make([]domain.DocumentResponse, 0, len(docs))
	for _, d := range docs {
		resp = append(resp, toDocumentResponse(d))
	}

	// Total is the real match count (previously len(page)).
	total, err := s.queries.CountDocuments(ctx, db.CountDocumentsParams{
		Column1: search,
		LOWER:   search,
		LOWER_2: search,
		LOWER_3: search,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to count documents: %w", err)
	}

	return &domain.DocumentListResponse{
		Documents: resp,
		Total:     int(total),
	}, nil
}

// Update modifies an existing document by merging provided fields.
func (s *DocumentService) Update(ctx context.Context, id int64, req domain.UpdateDocumentRequest) (*domain.DocumentResponse, error) {
	existing, err := s.queries.GetDocument(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDocumentNotFound
		}
		return nil, fmt.Errorf("failed to get document: %w", err)
	}

	params := db.UpdateDocumentParams{
		ID:          existing.ID,
		Title:       existing.Title,
		Type:        existing.Type,
		Url:         existing.Url,
		FilePath:    existing.FilePath,
		FileSize:    existing.FileSize,
		MimeType:    existing.MimeType,
		Description: existing.Description,
	}

	if req.Title != nil {
		params.Title = *req.Title
	}
	if req.URL != nil {
		params.Url = *req.URL
	}
	if req.Description != nil {
		params.Description = *req.Description
	}

	doc, err := s.queries.UpdateDocument(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update document: %w", err)
	}

	resp := toDocumentResponse(doc)
	return &resp, nil
}

// Delete soft-deletes a document by ID (stamps deleted_at). The row and its
// uploaded file stay on disk so Restore can undo; list/get queries filter the
// tombstone away.
func (s *DocumentService) Delete(ctx context.Context, id int64) error {
	affected, err := s.queries.DeleteDocument(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete document: %w", err)
	}
	if affected == 0 {
		return ErrDocumentNotFound
	}
	return nil
}

// Restore undoes a soft delete (the UI's delete-undo toast). Only clears the
// tombstone — the row and its file were never physically removed.
func (s *DocumentService) Restore(ctx context.Context, id int64) (*domain.DocumentResponse, error) {
	affected, err := s.queries.RestoreDocument(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to restore document: %w", err)
	}
	if affected == 0 {
		return nil, ErrDocumentNotFound
	}
	return s.Get(ctx, id)
}

// GetFile returns the file path and stored MIME type for a file-type document
// (for download/preview). The MIME type is what the upload whitelist validated
// — serving it verbatim (instead of letting http.ServeFile sniff) pins the
// Content-Type and stops an HTML-flavored .md from being sniffed as text/html
// on inline preview.
func (s *DocumentService) GetFile(ctx context.Context, id int64) (path string, mimeType string, err error) {
	doc, err := s.queries.GetDocument(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrDocumentNotFound
		}
		return "", "", fmt.Errorf("failed to get document: %w", err)
	}

	if doc.Type != string(domain.DocTypeFile) {
		return "", "", ErrNotFileDocument
	}

	return doc.FilePath, doc.MimeType, nil
}

// toDocumentResponse converts a db.Document to domain.DocumentResponse.
func toDocumentResponse(d db.Document) domain.DocumentResponse {
	return domain.DocumentResponse{
		ID:          d.ID,
		Title:       d.Title,
		Type:        d.Type,
		URL:         d.Url,
		FilePath:    d.FilePath,
		FileSize:    d.FileSize,
		MimeType:    d.MimeType,
		Description: d.Description,
		CreatedAt:   d.CreatedAt,
		UpdatedAt:   d.UpdatedAt,
	}
}
