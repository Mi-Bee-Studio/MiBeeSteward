package service

import (
	"bytes"
	"testing"
)

func TestDetectMimeType_JPEG(t *testing.T) {
	// JPEG magic bytes: FF D8 FF followed by JFIF/EXIF marker
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46}
	data = append(data, make([]byte, 500)...)

	mimeType := DetectMimeType(data)
	if mimeType != "image/jpeg" {
		t.Errorf("expected image/jpeg, got %s", mimeType)
	}
}

func TestDetectMimeType_PNG(t *testing.T) {
	// PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	data = append(data, make([]byte, 500)...)

	mimeType := DetectMimeType(data)
	if mimeType != "image/png" {
		t.Errorf("expected image/png, got %s", mimeType)
	}
}

func TestDetectMimeType_PDF(t *testing.T) {
	// PDF magic bytes: %PDF-
	data := []byte("%PDF-1.4 test content for pdf detection")
	data = append(data, make([]byte, 470)...)

	mimeType := DetectMimeType(data)
	if mimeType != "application/pdf" {
		t.Errorf("expected application/pdf, got %s", mimeType)
	}
}

func TestDetectMimeType_GIF(t *testing.T) {
	// GIF magic bytes: GIF89a
	data := []byte("GIF89a" + "test gif data padding")
	data = append(data, make([]byte, 490)...)

	mimeType := DetectMimeType(data)
	if mimeType != "image/gif" {
		t.Errorf("expected image/gif, got %s", mimeType)
	}
}

func TestDetectMimeType_Unknown(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}

	mimeType := DetectMimeType(data)
	if mimeType != "application/octet-stream" {
		t.Errorf("expected application/octet-stream, got %s", mimeType)
	}
}

func TestSaveFile_AllowedJPEG(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20) // 10 MB

	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46}
	jpegData = append(jpegData, make([]byte, 500)...)
	reader := bytes.NewReader(jpegData)

	_, _, _, mimeType, err := svc.SaveFile(reader, "photo.jpg", int64(len(jpegData)))
	if err != nil {
		t.Fatalf("expected no error for allowed JPEG, got: %v", err)
	}
	if mimeType != "image/jpeg" {
		t.Errorf("expected image/jpeg, got %s", mimeType)
	}
}

func TestSaveFile_AllowedPDF(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20)

	pdfData := []byte("%PDF-1.4 fake pdf content here")
	pdfData = append(pdfData, make([]byte, 480)...)
	reader := bytes.NewReader(pdfData)

	_, _, _, mimeType, err := svc.SaveFile(reader, "report.pdf", int64(len(pdfData)))
	if err != nil {
		t.Fatalf("expected no error for allowed PDF, got: %v", err)
	}
	if mimeType != "application/pdf" {
		t.Errorf("expected application/pdf, got %s", mimeType)
	}
}

func TestSaveFile_BlockedExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20)

	// Random binary data with .exe extension — should be rejected.
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 256)
	}
	reader := bytes.NewReader(data)

	_, _, _, _, err := svc.SaveFile(reader, "malware.exe", int64(len(data)))
	if err == nil {
		t.Fatal("expected error for blocked executable MIME type, got nil")
	}
}

func TestSaveFile_BlockedExtensionMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20)

	// JPEG content but .png extension — content vs extension mismatch.
	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46}
	jpegData = append(jpegData, make([]byte, 500)...)
	reader := bytes.NewReader(jpegData)

	_, _, _, _, err := svc.SaveFile(reader, "fake.png", int64(len(jpegData)))
	if err == nil {
		t.Fatal("expected error for content/extension mismatch, got nil")
	}
}

func TestSaveFile_ExceedsMaxSize(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 100) // 100 bytes max

	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	jpegData = append(jpegData, make([]byte, 500)...)
	reader := bytes.NewReader(jpegData)

	_, _, _, _, err := svc.SaveFile(reader, "big.jpg", int64(len(jpegData)))
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}
}
