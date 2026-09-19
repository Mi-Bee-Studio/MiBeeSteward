// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_ArgvMatrix drives the argv front door: too-few args, unknown
// subcommand, and a routed failure (each yields the right error shape).
func TestRun_ArgvMatrix(t *testing.T) {
	err := run([]string{"recog"})
	if !errors.Is(err, errUsage) {
		t.Fatalf("too-few args: want errUsage, got %v", err)
	}
	err = run([]string{"nmap", "x", "y"})
	if !errors.Is(err, errUsage) {
		t.Fatalf("unknown subcommand (nmap is NPSL and must not be importable): want errUsage, got %v", err)
	}
	// Routed failure: nonexistent source dir.
	err = run([]string{"recog", filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "out.yaml")})
	if err == nil || !strings.Contains(err.Error(), "fpimport recog") {
		t.Fatalf("want wrapped recog failure, got %v", err)
	}
}

// TestImportRecog_MixedDirBranches walks the dir-scan branches: a non-XML
// entry is skipped, malformed XML is warn-skipped, an unreadable file fails.
func TestImportRecog_MixedDirBranches(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(t.TempDir(), "rules.yaml")

	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not xml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.xml"), []byte("<fingerprints"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importRecog(dir, out); err != nil {
		t.Fatalf("skippable entries must not fail the import: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "notes.txt") {
		t.Fatalf("non-XML file leaked into output: %s", b)
	}

	// A DIRECTORY named *.xml is skipped by the IsDir guard, not read.
	if err := os.Mkdir(filepath.Join(dir, "subdir.xml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := importRecog(dir, out); err != nil {
		t.Fatalf("dir entry must be skipped: %v", err)
	}
}

// TestImportOUI_ErrorsAndPENErrors pins the single-file importers' failure
// wraps: unreadable input and bad destination both error out.
func TestImportOUI_ErrorsAndPENErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone.txt")
	out := filepath.Join(t.TempDir(), "out.yaml")

	if err := importOUI(missing, out); err == nil {
		t.Fatal("missing OUI input must error")
	}
	if err := importPEN(missing, out); err == nil {
		t.Fatal("missing PEN input must error")
	}

	// Output into a nonexistent directory fails at write time.
	in := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(in, []byte("00:00:0C\tCisco\t3"), 0o600); err != nil {
		t.Fatal(err)
	}
	badOut := filepath.Join(t.TempDir(), "no-such-dir", "out.yaml")
	if err := importOUI(in, badOut); err == nil {
		t.Fatal("OUI write into missing dir must error")
	}
	if err := os.WriteFile(in, []byte("iana,1,TestOrg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importPEN(in, badOut); err == nil {
		t.Fatal("PEN write into missing dir must error")
	}
}
