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

func TestSaveFile_AllowedMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20)

	mdData := []byte("# 运维手册\n\n- ICMP 探测\n- SNMP OID 表\n\n```bash\nnmap -sP 192.0.2.0/24\n```\n")
	mdData = append(mdData, bytes.Repeat([]byte(" "), 512-len(mdData))...)
	reader := bytes.NewReader(mdData)

	_, _, _, mimeType, err := svc.SaveFile(reader, "runbook.md", int64(len(mdData)))
	if err != nil {
		t.Fatalf("expected no error for allowed markdown, got: %v", err)
	}
	if mimeType != "text/markdown" {
		t.Errorf("expected text/markdown, got %s", mimeType)
	}
}

func TestSaveFile_MarkdownLeadingHTMLBlock(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20)

	// A .md starting with an HTML block sniffs as text/html; that is still
	// text/* content and must be accepted as markdown (sniffing cannot tell
	// the text family apart — sanitize happens at render time).
	mdData := []byte("<div class=\"note\">alert</div>\n\n# heading\n")
	mdData = append(mdData, bytes.Repeat([]byte(" "), 512-len(mdData))...)
	reader := bytes.NewReader(mdData)

	_, _, _, mimeType, err := svc.SaveFile(reader, "note.md", int64(len(mdData)))
	if err != nil {
		t.Fatalf("expected no error for markdown with leading HTML block, got: %v", err)
	}
	if mimeType != "text/markdown" {
		t.Errorf("expected text/markdown, got %s", mimeType)
	}
}

func TestSaveFile_BlockedBinaryNamedMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20)

	// Binary content named .md — the generic-detection exemption must NOT
	// apply to a text target; a .md has to actually be text.
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 256)
	}
	reader := bytes.NewReader(data)

	_, _, _, _, err := svc.SaveFile(reader, "malware.md", int64(len(data)))
	if err == nil {
		t.Fatal("expected error for binary content named .md, got nil")
	}
}

func TestSaveFile_BlockedPlainText(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewUploadService(tmpDir, 10<<20)

	// Plain .txt stays outside the whitelist (only markdown is supported).
	txtData := []byte("plain text meeting notes")
	txtData = append(txtData, bytes.Repeat([]byte(" "), 512-len(txtData))...)
	reader := bytes.NewReader(txtData)

	_, _, _, _, err := svc.SaveFile(reader, "notes.txt", int64(len(txtData)))
	if err == nil {
		t.Fatal("expected error for .txt upload, got nil")
	}
}

func TestNormalizeMime(t *testing.T) {
	cases := map[string]string{
		"text/plain; charset=utf-8": "text/plain",
		"text/markdown":             "text/markdown",
		"IMAGE/PNG":                 "image/png",
		"garbage":                   "garbage",
	}
	for in, want := range cases {
		if got := normalizeMime(in); got != want {
			t.Errorf("normalizeMime(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompatibleMime(t *testing.T) {
	cases := []struct {
		detected, ext string
		want          bool
	}{
		{"text/plain; charset=utf-8", "text/markdown", true},                                                 // text family
		{"text/html; charset=utf-8", "text/markdown", true},                                                  // text family
		{"image/jpeg", "image/jpeg", true},                                                                   // exact
		{"image/jpeg", "image/png", false},                                                                   // mismatch
		{"application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", true}, // Office container
		{"application/octet-stream", "text/markdown", false},                                                 // binary under text ext
	}
	for _, c := range cases {
		if got := compatibleMime(normalizeMime(c.detected), normalizeMime(c.ext)); got != c.want {
			t.Errorf("compatibleMime(%q, %q) = %v, want %v", c.detected, c.ext, got, c.want)
		}
	}
}
