package vendor

import (
	"os"
	"path/filepath"
	"strings"
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

// TestOUI_LongestPrefixMatch covers the critical correctness property of the
// three-tier (MA-S / MA-M / MA-L) lookup: a MAC must resolve to its LONGEST
// matching prefix, not the parent /24 OUI. This is mandatory because MA-S/MA-M
// sub-blocks are carved out of /24 OUIs owned by IEEE or another vendor.
//
// The canonical real-world example: Murata owns MA-S block 8C1F64B14 (/36)
// carved out of IEEE's pool OUI 8C1F64 (/24, registered to "IEEE Registration
// Authority"). A MAC 8C:1F:64:B1:4x:.. MUST resolve to Murata, NOT "IEEE
// Registration Authority" — which is what a naive /24-only lookup returns.
func TestOUI_LongestPrefixMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oui.txt")
	// Mix all three tiers. The 9-hex (MA-S) and 6-hex (MA-L) share the 8C1F64
	// stem; the 7-hex (MA-M) shares the B84C87 stem with its parent /24.
	content := []byte(strings.Join([]string{
		"# MA-L /24 (6 hex)",
		"8C1F64\tIEEE Registration Authority",
		"B84C87\tSome Other Vendor (MA-L parent)",
		"BCAD28\tHikvision Digital Technology",
		"# MA-M /28 (7 hex) — sub-block of B84C87",
		"B84C879\tAirgain Inc.",
		"# MA-S /36 (9 hex) — sub-block of 8C1F64 (IEEE pool)",
		"8C1F64B14\tMurata Manufacturing Co., Ltd.",
	}, "\n"))
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	o := New()
	if err := o.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	cases := []struct {
		name       string
		mac        string
		wantVendor string
		wantPrefix string
	}{
		{
			name:       "MA-S wins over parent MA-L (Murata, not IEEE)",
			mac:        "8c:1f:64:b1:4a:bc",
			wantVendor: "Murata Manufacturing Co., Ltd.",
			wantPrefix: "8C1F64B14", // 9-hex, NOT the 6-hex parent
		},
		{
			name:       "MA-M wins over parent MA-L (Airgain)",
			mac:        "b8:4c:87:9a:bb:cc",
			wantVendor: "Airgain Inc.",
			wantPrefix: "B84C879", // 7-hex
		},
		{
			name:       "MA-L only (no sub-block) → /24 vendor",
			mac:        "bc:ad:28:11:22:33",
			wantVendor: "Hikvision Digital Technology",
			wantPrefix: "BCAD28", // 6-hex
		},
		{
			name:       "parent MA-L when MAC is in /24 but no sub-block matches",
			mac:        "8c:1f:64:ff:ee:dd", // B14 is the MA-S block; FF.. is not
			wantVendor: "IEEE Registration Authority",
			wantPrefix: "8C1F64", // falls through to the 6-hex parent
		},
		{
			name:       "unknown MAC",
			mac:        "aa:bb:cc:dd:ee:ff",
			wantVendor: "",
			wantPrefix: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotVendor, gotPrefix := o.LookupFull(c.mac)
			if gotVendor != c.wantVendor {
				t.Errorf("LookupFull(%q) vendor = %q, want %q", c.mac, gotVendor, c.wantVendor)
			}
			if gotPrefix != c.wantPrefix {
				t.Errorf("LookupFull(%q) prefix = %q, want %q", c.mac, gotPrefix, c.wantPrefix)
			}
			// Lookup (the thin wrapper) must agree on the vendor.
			if got := o.Lookup(c.mac); got != c.wantVendor {
				t.Errorf("Lookup(%q) = %q, want %q (disagrees with LookupFull)", c.mac, got, c.wantVendor)
			}
		})
	}
}

// TestOUI_LoadEmbeddedCurated verifies the out-of-box seed: LoadEmbeddedCurated
// populates the table from the //go:embed oui_curated.txt asset so a fresh
// install (no scanner.oui_path configured) still gets vendor inference for the
// common vendors the curated table covers.
func TestOUI_LoadEmbeddedCurated(t *testing.T) {
	o := New()
	if o.Loaded() {
		t.Fatal("fresh OUI should not be Loaded()")
	}
	o.LoadEmbeddedCurated()
	if !o.Loaded() {
		t.Fatal("LoadEmbeddedCurated should mark the table Loaded()")
	}
	if o.Size() == 0 {
		t.Fatal("LoadEmbeddedCurated should populate at least one entry")
	}
	// Hikvision (BCAD28) is a canonical curated entry — verify it resolves.
	got, prefix := o.LookupFull("bc:ad:28:11:22:33")
	if !strings.Contains(strings.ToLower(got), "hikvision") {
		t.Errorf("LookupFull(bcad28..) vendor = %q, want a Hikvision match", got)
	}
	if prefix != "BCAD28" {
		t.Errorf("LookupFull(bcad28..) prefix = %q, want BCAD28", prefix)
	}
	// An unknown prefix should still return "" (the curated table is a subset).
	if got := o.Lookup("aa:bb:cc:dd:ee:ff"); got != "" {
		t.Errorf("Lookup on unknown prefix should be empty, got %q", got)
	}
}
