package service

import (
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

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
		return "", "", 0, "", fmt.Errorf("file size %d exceeds maximum allowed size %d", size, s.maxFileSize)
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

	// Get MIME type from file extension
	extMime := mime.TypeByExtension(filepath.Ext(header))

	// Allowed MIME types whitelist
	var allowedMIMETypes = map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
		"application/pdf": true,
		"application/msword": true,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": true,
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	}

	// Determine effective MIME: prefer content-detected type when specific,
	// fall back to extension-based type for Office formats that http.DetectContentType
	// cannot distinguish (all detect as application/zip)
	mimeType = detectedMime
	if !allowedMIMETypes[mimeType] && allowedMIMETypes[extMime] {
		mimeType = extMime
	}

	// Check detected MIME against whitelist
	if !allowedMIMETypes[mimeType] {
		slog.Warn("file upload rejected", "filename", header, "reason", fmt.Sprintf("mime type not allowed: %s", detectedMime))
		return "", "", 0, "", fmt.Errorf("file type not allowed: %s", detectedMime)
	}

	// Verify content MIME matches extension (when content detection is specific)
	if extMime != "" && detectedMime != extMime {
		// Skip mismatch check for generic types that http.DetectContentType can't distinguish
		if detectedMime != "application/zip" && detectedMime != "application/octet-stream" {
			slog.Warn("file upload rejected", "filename", header, "reason", "content does not match extension")
			return "", "", 0, "", fmt.Errorf("file content does not match extension")
		}
	}

	// Generate UUID filename
	ext := filepath.Ext(header)
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
