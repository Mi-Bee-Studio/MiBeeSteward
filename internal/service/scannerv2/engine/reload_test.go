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

// TestStartupLoadsManagedCorpus: with no explicit FingerprintPath, a managed
// dir holding a corpus must be loaded at construction — otherwise a restart
// silently reverts the engine to the embedded corpus while the admin UI still
// reports the managed one (engine rev vs status rev mismatch).
func TestStartupLoadsManagedCorpus(t *testing.T) {
	managed := t.TempDir()
	writeCorpus(t, managed, 3)

	eng, err := NewEngine(nil, Config{FingerprintManagedDir: managed}, nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	rev, rules := eng.CorpusFacts()
	if rules != 3 {
		t.Fatalf("managed corpus not loaded at startup: rules=%d", rules)
	}

	// The startup path and an explicit-path load of the same corpus must
	// agree on the content revision (same hash, same count).
	ref, err := NewEngine(nil, Config{FingerprintPath: managed}, nil)
	if err != nil {
		t.Fatalf("reference engine: %v", err)
	}
	refRev, refRules := ref.CorpusFacts()
	if rev != refRev || rules != refRules {
		t.Fatalf("managed-dir startup facts %q/%d != explicit-path %q/%d", rev, rules, refRev, refRules)
	}
}

// TestStartupFingerprintPathWinsOverManaged: an operator-explicit
// FingerprintPath outranks the managed dir.
func TestStartupFingerprintPathWinsOverManaged(t *testing.T) {
	explicit := t.TempDir()
	writeCorpus(t, explicit, 2)
	managed := t.TempDir()
	writeCorpus(t, managed, 7)

	eng, err := NewEngine(nil, Config{FingerprintPath: explicit, FingerprintManagedDir: managed}, nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if _, rules := eng.CorpusFacts(); rules != 2 {
		t.Fatalf("explicit path must win: rules=%d", rules)
	}
}

// TestStartupManagedEmptyFallsBackToEmbedded: an empty (or missing) managed
// dir must leave the engine on the embedded corpus, matching a no-dirs build.
func TestStartupManagedEmptyFallsBackToEmbedded(t *testing.T) {
	empty := t.TempDir() // exists, holds no yaml

	eng, err := NewEngine(nil, Config{FingerprintManagedDir: empty}, nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	base, err := NewEngine(nil, Config{}, nil)
	if err != nil {
		t.Fatalf("baseline engine: %v", err)
	}
	rev, rules := eng.CorpusFacts()
	baseRev, baseRules := base.CorpusFacts()
	if rules == 0 || baseRules == 0 {
		t.Fatalf("embedded corpus missing: %d/%d", rules, baseRules)
	}
	if rev != baseRev || rules != baseRules {
		t.Fatalf("empty managed dir changed facts: %q/%d vs %q/%d", rev, rules, baseRev, baseRules)
	}
}
