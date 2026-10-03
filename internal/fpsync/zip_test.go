// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

package fpsync

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func zipCorpus(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestZipRoundTripAndSniffing(t *testing.T) {
	zb := zipCorpus(t, corpusFixture())
	if !IsZip(zb) || IsTarGz(zb) {
		t.Fatal("zip magic sniffing failed")
	}
	tgz, _ := TarGz(corpusFixture())
	if !IsTarGz(tgz) || IsZip(tgz) {
		t.Fatal("tar.gz magic sniffing failed")
	}
	dir := t.TempDir()
	names, err := ExtractZip(dir, zb)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("want 2 files, got %v", names)
	}
	for name, want := range corpusFixture() {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != string(want) {
			t.Errorf("file %s mutated/unreadable: %v", name, err)
		}
	}
}

func TestExtractZipRejectsHostileArchives(t *testing.T) {
	dir := t.TempDir()
	if _, err := ExtractZip(dir, zipCorpus(t, map[string][]byte{"evil.sh": []byte("#!/bin/sh\n")})); err == nil {
		t.Error("non-yaml entry must be rejected")
	}
	if _, err := ExtractZip(dir, zipCorpus(t, map[string][]byte{"../escape.yaml": []byte("version: 1\n")})); err == nil {
		t.Error("traversal name must be rejected")
	}
	if _, err := ExtractZip(dir, zipCorpus(t, map[string][]byte{"sub/inner.yaml": []byte("version: 1\n")})); err == nil {
		t.Error("nested path must be rejected")
	}
}
