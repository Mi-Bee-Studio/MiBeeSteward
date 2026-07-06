package probe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseARPFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arp")
	// Mimic the /proc/net/arp layout. Note the header row + a couple of
	// incomplete entries (00:00:00:00:00:00) that must be skipped.
	content := []byte(`IP address       HW type     Flags       HW address            Mask     Device
192.168.63.1     0x1         0x2         bc:ad:28:11:22:33     *        enp3s0
192.168.63.101   0x1         0x2         00:1a:2b:3c:4d:5e     *        enp3s0
192.168.63.246   0x1         0x2         00:00:00:00:00:00     *        enp3s0
192.168.63.133   0x1         0x2         AA:BB:CC:DD:EE:FF     *        wlan0
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// Reset the process-wide cache so this test isn't polluted by an earlier read.
	cachedARP.Lock()
	cachedARP.entries = nil
	cachedARP.at = time.Time{} // zero → forces a fresh parse on next read
	cachedARP.Unlock()

	entries, err := parseARPFile(path)
	if err != nil {
		t.Fatalf("parseARPFile: %v", err)
	}
	if got := len(entries); got != 3 {
		t.Errorf("got %d entries, want 3 (incomplete entry must be skipped)", got)
	}
	// MACs are normalized to lowercase.
	if e, ok := entries["192.168.63.1"]; !ok || e.mac != "bc:ad:28:11:22:33" || e.device != "enp3s0" {
		t.Errorf("entry for .1 = %+v, want bc:ad:28:11:22:33/enp3s0", e)
	}
	if e, ok := entries["192.168.63.133"]; !ok || e.mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("entry for .133 should be lowercase, got %+v", e)
	}
	// Incomplete resolution must NOT appear.
	if _, ok := entries["192.168.63.246"]; ok {
		t.Error("incomplete ARP entry (all-zero MAC) should be skipped")
	}
}

func TestLookupMACOnce_FindsAndMisses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "arp")
	content := []byte(`IP address       HW type     Flags       HW address            Mask     Device
10.0.0.5         0x1         0x2         11:22:33:44:55:66     *        eth0
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// parseARPFile reads from the path we pass; lookupMACOnce uses the hardcoded
	// /proc/net/arp, so we test parseARPFile + a manual map lookup instead.
	entries, err := parseARPFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := entries["10.0.0.5"]; !ok || e.mac != "11:22:33:44:55:66" {
		t.Errorf("expected entry for 10.0.0.5, got %+v", e)
	}
	if _, ok := entries["10.0.0.99"]; ok {
		t.Error("10.0.0.99 should be a miss")
	}
}
