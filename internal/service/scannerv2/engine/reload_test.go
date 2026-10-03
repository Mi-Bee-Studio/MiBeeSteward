// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCorpus(t *testing.T, dir string, rules int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "version: 1\nrules:\n"
	for i := 0; i < rules; i++ {
		body += "  - id: r" + string(rune('a'+i)) + "\n    match: {op: contains, value: \"probe\"}\n    service: svc\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "banner.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReloadFingerprintsHotSwap: the corpus facts move with a reload and a
// rejected corpus leaves the live one untouched.
func TestReloadFingerprintsHotSwap(t *testing.T) {
	dirA := t.TempDir()
	writeCorpus(t, dirA, 2)
	eng, err := NewEngine(nil, Config{FingerprintPath: dirA}, nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	rev1, rules1 := eng.CorpusFacts()
	if rules1 != 2 || rev1 == "" {
		t.Fatalf("initial facts: rev=%q rules=%d", rev1, rules1)
	}

	dirB := t.TempDir()
	writeCorpus(t, dirB, 5)
	rev2, rules2, err := eng.ReloadFingerprints(dirB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rules2 != 5 || rev2 == rev1 {
		t.Fatalf("post-reload facts: rev=%q rules=%d", rev2, rules2)
	}
	if gotRev, gotRules := eng.CorpusFacts(); gotRev != rev2 || gotRules != 5 {
		t.Fatalf("CorpusFacts after reload: %q/%d", gotRev, gotRules)
	}

	// A corpus the loader rejects must NOT displace the live one.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "broken.yaml"),
		[]byte("version: 1\nrules:\n  - id: x\n    match: {op: regex, value: \"(unclosed[\"}\n    service: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := eng.ReloadFingerprints(bad, nil); err == nil {
		t.Fatal("broken corpus must be rejected")
	}
	if gotRev, gotRules := eng.CorpusFacts(); gotRev != rev2 || gotRules != 5 {
		t.Fatalf("rejected reload changed live corpus: %q/%d", gotRev, gotRules)
	}
}
