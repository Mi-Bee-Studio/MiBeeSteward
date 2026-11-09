// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return len(s) > 0
}

// The instance ID is the App-side bind/merge anchor (Scout docs/02 §8): it
// must be generated once, persisted across restarts, and stable on reload.
func TestLoadIdentityCreatesStableID(t *testing.T) {
	dir := t.TempDir()

	first := LoadIdentity(dir, "", testLogger())
	if len(first.ID) != 32 || !isHex(first.ID) {
		t.Fatalf("first ID = %q, want 32 lowercase hex chars", first.ID)
	}

	again := LoadIdentity(dir, "", testLogger())
	if again.ID != first.ID {
		t.Fatalf("ID not stable across loads: %q vs %q", first.ID, again.ID)
	}

	b, err := os.ReadFile(filepath.Join(dir, instanceIDFile))
	if err != nil {
		t.Fatalf("read persisted id file: %v", err)
	}
	if string(b) != first.ID {
		t.Fatalf("persisted id = %q, want %q", string(b), first.ID)
	}
}

// A corrupted file (truncated / non-hex / wrong length) must not poison the
// identity forever: regenerate and rewrite.
func TestLoadIdentityRegeneratesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, instanceIDFile), []byte("not-an-id"), 0o644); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	ident := LoadIdentity(dir, "", testLogger())
	if len(ident.ID) != 32 || !isHex(ident.ID) {
		t.Fatalf("corrupt file did not regenerate: ID = %q", ident.ID)
	}
	b, err := os.ReadFile(filepath.Join(dir, instanceIDFile))
	if err != nil || string(b) != ident.ID {
		t.Fatalf("regenerated id not persisted back (err=%v, file=%q)", err, string(b))
	}
}

// Unwritable data dir: identity degrades to an ephemeral per-process ID (warn
// logged at the call site) instead of blocking boot — discovery is optional,
// the server is not.
func TestLoadIdentityUnwritableDirEphemeral(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based unwritable-dir test is POSIX-only")
	}
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.MkdirAll(ro, 0o500); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}

	id1 := LoadIdentity(ro, "", testLogger()).ID
	id2 := LoadIdentity(ro, "", testLogger()).ID
	if id1 == "" || id2 == "" {
		t.Fatalf("ephemeral degradation returned empty IDs: %q / %q", id1, id2)
	}
	if id1 == id2 {
		t.Fatalf("unwritable dir should yield ephemeral IDs, got twice %q", id1)
	}
}

// Name resolution: explicit override wins (trimmed); empty override falls
// back to the OS hostname; a hostname failure falls back to a static name.
// Empty/whitespace result is never announced.
func TestLoadIdentityNameResolution(t *testing.T) {
	dir := t.TempDir()

	if got := LoadIdentity(dir, "  edge-name  ", testLogger()).Name; got != "edge-name" {
		t.Fatalf("override name = %q, want %q", got, "edge-name")
	}

	fallback := LoadIdentity(dir, "", testLogger()).Name
	if fallback == "" {
		t.Fatalf("empty override should resolve to hostname/static fallback, got empty")
	}
}
