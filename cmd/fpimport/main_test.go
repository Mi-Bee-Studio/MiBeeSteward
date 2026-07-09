package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestImportRecog_Smoke converts a tiny Recog XML fragment and checks the
// output YAML has one rule with source: recog.
func TestImportRecog_Smoke(t *testing.T) {
	dir := t.TempDir()
	xml := `<?xml version="1.0"?>
<matches>
  <fingerprint pattern="SSH-2\.0-OpenSSH_(\S+)" flags="REG_ICASE">
    <param pos="0" name="service" value="ssh"/>
    <param pos="1" name="service.version" value=""/>
  </fingerprint>
</matches>`
	if err := os.WriteFile(filepath.Join(dir, "ssh_banners.xml"), []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "recog.yaml")
	if err := importRecog(dir, out); err != nil {
		t.Fatalf("importRecog: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !contains(s, "source: recog") {
		t.Errorf("output missing source: recog\n%s", s)
	}
	if !contains(s, "service: ssh") {
		t.Errorf("output missing service: ssh\n%s", s)
	}
}

func TestImportOUI_Smoke(t *testing.T) {
	in := filepath.Join(t.TempDir(), "oui.txt")
	// IEEE raw format with (hex)/(base 16) lines.
	ouiData := "BC-AD-28   (hex)        Hikvision Digital Technology\n" +
		"BCAD28     (base 16)    Hikvision Digital Technology\n" +
		"00-1B-44   (hex)        Cisco Systems\n"
	if err := os.WriteFile(in, []byte(ouiData), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "oui-out.txt")
	if err := importOUI(in, out); err != nil {
		t.Fatalf("importOUI: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !contains(s, "BCAD28\tHikvision Digital Technology") {
		t.Errorf("output missing Hikvision entry\n%s", s)
	}
	if !contains(s, "001B44\tCisco Systems") {
		t.Errorf("output missing Cisco entry\n%s", s)
	}
}

func TestImportPEN_Smoke(t *testing.T) {
	in := filepath.Join(t.TempDir(), "pen.csv")
	csv := "Registration Date,Registry,Organization,Private Enterprise Number\n" +
		"2020-01-01,IANA,Cisco Systems,9\n" +
		"2021-05-10,IANA,Hikvision,39165\n"
	if err := os.WriteFile(in, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "pen.yaml")
	if err := importPEN(in, out); err != nil {
		t.Fatalf("importPEN: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !contains(s, "1.3.6.1.4.1.9.") {
		t.Errorf("output missing Cisco OID prefix\n%s", s)
	}
	if !contains(s, "1.3.6.1.4.1.39165.") {
		t.Errorf("output missing Hikvision OID prefix\n%s", s)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
