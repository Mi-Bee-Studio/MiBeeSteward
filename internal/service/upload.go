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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// Typed upload rejection reasons — the HTTP handler maps each to a distinct
// status code (413/415/400) so the client sees WHY the file was refused,
// instead of a blanket 500.
var (
	ErrFileTooLarge       = errors.New("file exceeds the maximum allowed size")
	ErrFileTypeNotAllowed = errors.New("file type not allowed")
	ErrFileMismatch       = errors.New("file content does not match its extension")
)

// allowedMIMETypes is the upload whitelist. Comparisons happen on NORMALIZED
// media types (parameters like "; charset=utf-8" stripped first) because
// http.DetectContentType appends parameters to text types but not binary ones.
var allowedMIMETypes = map[string]bool{
	"image/jpeg":         true,
	"image/png":          true,
	"image/gif":          true,
	"application/pdf":    true,
	"application/msword": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"text/markdown": true,
}

// extMimeOverrides hard-codes extension→MIME for text types whose mapping is
// missing from minimal hosts (distroless/alpine without shared-mime-info):
// mime.TypeByExtension(".md") returns "" there, which would make the
// extension fallback in SaveFile fail portably.
var extMimeOverrides = map[string]string{
	".md":       "text/markdown",
	".markdown": "text/markdown",
}

// normalizeMime strips media-type parameters ("; charset=utf-8") and lowers
// the case, so whitelist comparisons don't depend on detector-specific
// parameter suffixes.
func normalizeMime(v string) string {
	if mt, _, err := mime.ParseMediaType(v); err == nil {
		return strings.ToLower(mt)
	}
	return strings.ToLower(v)
}

// isTextMime reports whether v is any text/* type.
func isTextMime(v string) bool {
	return strings.HasPrefix(v, "text/")
}

// compatibleMime reports whether sniffed content (detected) may carry a
// filename extension claiming ext:
//   - Generic detections the sniffer cannot distinguish (all Office formats
//     sniff as application/zip) are accepted — but NOT for a text/* target:
//     binary content named .md is a mismatch, a .md must actually be text.
//   - The text/* family is one sniffing group (plain text, markdown and HTML
//     all detect as text/plain or text/html), so any text/* content validates
//     any text/* extension. The security boundary for text is elsewhere:
//     render-side sanitization + forced-attachment downloads with nosniff.
func compatibleMime(detected, ext string) bool {
	if detected == "application/zip" || detected == "application/octet-stream" {
		return !isTextMime(ext)
	}
	if isTextMime(detected) && isTextMime(ext) {
		return true
	}
	return detected == ext
}

// UploadService handles file upload operations.
type UploadService struct {
	uploadDir   string
	maxFileSize int64
}

// NewUploadService creates a new UploadService.
func NewUploadService(uploadDir string, maxFileSize int64) *UploadService {
	return &UploadService{
		uploadDir:   uploadDir,
		maxFileSize: maxFileSize,
	}
}

// SaveFile saves an uploaded file to disk with a UUID filename.
// Returns the relative file path, original filename, file size, and mime type.
func (s *UploadService) SaveFile(file io.Reader, header string, size int64) (filePath string, fileName string, fileSize int64, mimeType string, err error) {
	if size > s.maxFileSize {
		slog.Warn("file upload rejected", "filename", header, "size", size, "reason", "exceeds max file size")
		return "", "", 0, "", fmt.Errorf("%w (%d > %d bytes)", ErrFileTooLarge, size, s.maxFileSize)
	}

	// Ensure upload directory exists
	if err := os.MkdirAll(s.uploadDir, 0755); err != nil {
		return "", "", 0, "", fmt.Errorf("failed to create upload directory: %w", err)
	}

	// Read first 512 bytes for MIME type detection from content
	buf := make([]byte, 512)
	n, _ := io.ReadFull(file, buf)
	buf = buf[:n]

	// Detect MIME type from file content
	detectedMime := DetectMimeType(buf)

	// Get MIME type from file extension, with hard-coded overrides for text
	// types (see extMimeOverrides for why TypeByExtension alone is not portable).
	ext := filepath.Ext(header)
	extMime := extMimeOverrides[ext]
	if extMime == "" {
		extMime = mime.TypeByExtension(ext)
	}

	// All comparisons on normalized (parameter-stripped) media types: sniffed
	// text types carry "; charset=utf-8", which would never equal a bare
	// whitelist key like "text/markdown".
	detectedNorm := normalizeMime(detectedMime)
	extNorm := normalizeMime(extMime)

	// Determine effective MIME: prefer content-detected type when specific,
	// fall back to extension-based type for Office formats that http.DetectContentType
	// cannot distinguish (all detect as application/zip) and for markdown
	// (sniffs as text/plain).
	mimeType = detectedNorm
	if !allowedMIMETypes[mimeType] && allowedMIMETypes[extNorm] {
		mimeType = extNorm
	}

	// Check effective MIME against whitelist
	if !allowedMIMETypes[mimeType] {
		slog.Warn("file upload rejected", "filename", header, "reason", fmt.Sprintf("mime type not allowed: %s", detectedMime))
		return "", "", 0, "", fmt.Errorf("%w: %s", ErrFileTypeNotAllowed, detectedMime)
	}

	// Verify content MIME is compatible with the extension (when both are
	// specific). See compatibleMime for the text/* and generic-container rules.
	if extNorm != "" && !compatibleMime(detectedNorm, extNorm) {
		slog.Warn("file upload rejected", "filename", header, "reason", "content does not match extension")
		return "", "", 0, "", ErrFileMismatch
	}

	// Generate UUID filename (extension already resolved above)
	uuidName := uuid.New().String() + ext
	destPath := filepath.Join(s.uploadDir, uuidName)

	// Create destination file
	dst, err := os.Create(destPath)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to create file: %w", err)
	}
	defer dst.Close()

	// Write peeked header bytes first
	if _, err := dst.Write(buf); err != nil {
		os.Remove(destPath)
		return "", "", 0, "", fmt.Errorf("failed to save file: %w", err)
	}

	// Copy remaining content with size limit (accounting for bytes already written)
	remainingLimit := s.maxFileSize + 1 - int64(len(buf))
	if remainingLimit < 0 {
		remainingLimit = 0
	}
	written, err := io.Copy(dst, io.LimitReader(file, remainingLimit))
	if err != nil {
		os.Remove(destPath)
		return "", "", 0, "", fmt.Errorf("failed to save file: %w", err)
	}
	written += int64(len(buf))

	if written > s.maxFileSize {
		os.Remove(destPath)
		slog.Warn("file upload rejected", "filename", header, "size", size, "reason", "exceeds maximum allowed size after write")
		return "", "", 0, "", fmt.Errorf("file size exceeds maximum allowed size %d", s.maxFileSize)
	}

	slog.Info("file uploaded", "filename", filepath.Base(header), "size", written, "mime", mimeType)
	return destPath, filepath.Base(header), written, mimeType, nil
}

// DetectMimeType detects the MIME type from file content.
func DetectMimeType(data []byte) string {
	mimeType := http.DetectContentType(data)
	return mimeType
}
