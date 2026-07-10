package classify

import (
	"os"
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

// TestRegexCapture verifies the regex_capture extractor: a Recog-imported rule
// with a capture group in its match pattern can extract a named value (version)
// from that group. This is the feature that unlocks Recog's version extraction
// (853 version extractors in the imported corpus).
func TestRegexCapture(t *testing.T) {
	dir := t.TempDir()
	yaml := `version: 1
rules:
  - id: test-version
    match: { field: banner, op: regex, value: "^SSH-2\\.0-OpenSSH_(\\S+)" }
    service: ssh
    protocol: tcp
    confidence: 0.9
    extract:
      metadata:
        version: { regex_capture: 1 }
`
	if err := os.WriteFile(dir+"/test.yaml", []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := &RuleClassifier{}
	if err := rc.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 22, Confidence: 0.9, RawData: map[string]string{"banner": "SSH-2.0-OpenSSH_9.0p2 Debian-7"}},
	}
	out := rc.Classify(ev)
	if len(out) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(out))
	}
	if out[0].Metadata["version"] != "9.0p2" {
		t.Errorf("regex_capture version = %q, want 9.0p2", out[0].Metadata["version"])
	}
}

// TestRegexCapture_WithTransform verifies regex_capture works alongside the
// banner-strip transform (the combination Recog ssh.banner rules need: strip
// "SSH-x.y-" first, then capture from the software string).
func TestRegexCapture_WithTransform(t *testing.T) {
	dir := t.TempDir()
	// Recog ssh.banner pattern matches the software string after "SSH-x.y-".
	// pattern "^OpenSSH_(\S+)" with transform strip_ssh_prefix.
	yaml := `version: 1
rules:
  - id: test-ssh-version
    match: { field: banner, op: regex, value: "^OpenSSH_(\\S+)", transform: strip_ssh_prefix }
    service: ssh
    protocol: tcp
    confidence: 0.9
    extract:
      metadata:
        version: { regex_capture: 1 }
        inferred_brand: { const: "OpenBSD" }
`
	if err := os.WriteFile(dir+"/test.yaml", []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := &RuleClassifier{}
	if err := rc.LoadFromDir(dir); err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	ev := []scannerv2.Evidence{
		{Kind: "banner", Port: 22, Confidence: 0.9, RawData: map[string]string{"banner": "SSH-2.0-OpenSSH_8.4p1 Ubuntu"}},
	}
	out := rc.Classify(ev)
	if len(out) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(out))
	}
	if out[0].Metadata["version"] != "8.4p1" {
		t.Errorf("version = %q, want 8.4p1 (strip + capture)", out[0].Metadata["version"])
	}
	if out[0].Metadata["inferred_brand"] != "OpenBSD" {
		t.Errorf("brand = %q, want OpenBSD", out[0].Metadata["inferred_brand"])
	}
}
