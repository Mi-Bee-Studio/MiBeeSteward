package vendor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeMACPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"bc:ad:28:11:22:33", "BCAD28"},
		{"BC-AD-28-11-22-33", "BCAD28"},
		{"BCAD28112233", "BCAD28"},
		{"bcad28112233", "BCAD28"},
		{"bc.ad.28.11.22.33", "BCAD28"},
		{"", ""},
		{"abc", ""},
		{"zz:ad:28", ""}, // non-hex
		{"bc:ad", ""},    // too short
	}
	for _, c := range cases {
		if got := NormalizeMACPrefix(c.in); got != c.want {
			t.Errorf("NormalizeMACPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseOUILine_BothFormats(t *testing.T) {
	cases := []struct{ line, wantPrefix, wantVendor string }{
		// Curated MiBee format: <hex>\t<vendor>
		{"BCAD28\tHikvision Digital Technology", "BCAD28", "Hikvision Digital Technology"},
		// IEEE oui.txt (hex) format
		{"BC-AD-28   (hex)        Hikvision Digital Technology", "BCAD28", "Hikvision Digital Technology"},
		// IEEE oui.txt (base 16) format — same prefix, should also parse
		{"BCAD28     (base 16)    Hikvision Digital Technology", "BCAD28", "Hikvision Digital Technology"},
		// Garbage / comment lines
		{"  ", "", ""},
		{"OUI\tVendor", "OUI", "Vendor"}, // 3-hex "OUI" fails (O not hex) → prefix ""
		{"# comment", "", ""},
	}
	for _, c := range cases {
		// "OUI\tVendor" case: "O" is non-hex so prefix is "" — adjust expectation
		if c.line == "OUI\tVendor" {
			c.wantPrefix = ""
		}
		prefix, vendor := parseOUILine(c.line)
		if prefix != c.wantPrefix || vendor != c.wantVendor {
			t.Errorf("parseOUILine(%q) = (%q,%q), want (%q,%q)",
				c.line, prefix, vendor, c.wantPrefix, c.wantVendor)
		}
	}
}

func TestOUI_LoadAndLookup(t *testing.T) {
	// Write a small OUI file mixing both formats.
	dir := t.TempDir()
	path := filepath.Join(dir, "oui.txt")
	content := []byte("BCAD28\tHikvision Digital Technology\n" +
		"F0:9F:C2   (hex)        Apple, Inc.\n" +
		"000C29     (base 16)    VMware, Inc.\n" +
		"\n" +
		"# comment line\n" +
		"invalid line with no tab or parens\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	o := New()
	if err := o.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !o.Loaded() {
		t.Fatal("Loaded() = false after successful load")
	}
	if o.Size() != 3 {
		t.Errorf("Size = %d, want 3 (Hikvision, Apple, VMware)", o.Size())
	}

	cases := []struct{ mac, want string }{
		{"bc:ad:28:11:22:33", "Hikvision Digital Technology"},
		{"BC-AD-28-99-88-77", "Hikvision Digital Technology"}, // case-insensitive
		{"f0:9f:c2:00:00:01", "Apple, Inc."},
		{"00:0c:29:aa:bb:cc", "VMware, Inc."},
		{"aa:bb:cc:dd:ee:ff", ""}, // unknown prefix
	}
	for _, c := range cases {
		if got := o.Lookup(c.mac); got != c.want {
			t.Errorf("Lookup(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}

func TestOUI_MissingFileSilentDegradation(t *testing.T) {
	o := New()
	if err := o.Load("/nonexistent/path/oui.txt"); err != nil {
		t.Errorf("missing file should not return error, got %v", err)
	}
	if o.Loaded() {
		t.Error("Loaded() should be false for missing file")
	}
	if got := o.Lookup("bc:ad:28:11:22:33"); got != "" {
		t.Errorf("Lookup on empty table should return empty, got %q", got)
	}
}

func TestOUI_EmptyPathIsNoop(t *testing.T) {
	o := New()
	if err := o.Load(""); err != nil {
		t.Errorf("empty path should not error, got %v", err)
	}
	if o.Loaded() {
		t.Error("empty path should leave Loaded() false")
	}
}

func TestNilOUIIsSafe(t *testing.T) {
	var o *OUI
	if o.Loaded() {
		t.Error("nil OUI Loaded() should be false")
	}
	if got := o.Lookup("bc:ad:28:11:22:33"); got != "" {
		t.Errorf("nil OUI Lookup should return empty, got %q", got)
	}
	if o.Size() != 0 {
		t.Errorf("nil OUI Size should be 0, got %d", o.Size())
	}
}
