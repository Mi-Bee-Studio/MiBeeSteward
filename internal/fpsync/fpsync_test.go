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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func corpusFixture() map[string][]byte {
	return map[string][]byte{
		"banner.yaml": []byte("version: 1\nrules:\n  - id: a\n    match: {op: contains, value: \"OpenSSH\"}\n    service: ssh\n"),
		"ports.yaml":  []byte("version: 1\nrules: []\n"),
	}
}

func TestHashIsContentAddressed(t *testing.T) {
	a := Hash(corpusFixture())
	if b := Hash(corpusFixture()); a != b {
		t.Fatalf("hash not deterministic: %s vs %s", a, b)
	}
	c := corpusFixture()
	c["banner.yaml"] = append(c["banner.yaml"], '\n')
	if Hash(c) == a {
		t.Fatal("content change must change the revision")
	}
	d := corpusFixture()
	d["renamed.yaml"] = d["ports.yaml"]
	delete(d, "ports.yaml")
	if Hash(d) == a {
		t.Fatal("rename must change the revision")
	}
}

func TestTarRoundTrip(t *testing.T) {
	tarGz, err := TarGz(corpusFixture())
	if err != nil {
		t.Fatal(err)
	}
	again, _ := TarGz(corpusFixture())
	if string(tarGz) != string(again) {
		t.Fatal("envelope not deterministic")
	}
	dir := t.TempDir()
	names, err := ExtractTarGz(dir, tarGz)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("want 2 files, got %v", names)
	}
	for name, want := range corpusFixture() {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("file %s mutated in transit", name)
		}
	}
}

func TestExtractRejectsHostileArchives(t *testing.T) {
	dir := t.TempDir()
	// Non-yaml extension.
	tgz, _ := TarGz(map[string][]byte{"evil.sh": []byte("#!/bin/sh\n")})
	if _, err := ExtractTarGz(dir, tgz); err == nil {
		t.Error("non-yaml entry must be rejected")
	}
	// Traversal-shaped member name (hand-built: TarGz itself never produces
	// one, so pack a raw tar header with an escaping path).
	if _, err := ExtractTarGz(dir, gzTarMember("../escape.yaml")); err == nil {
		t.Error("traversal name must be rejected")
	}
	// File-count cap.
	many := make(map[string][]byte)
	for i := 0; i < MaxFileCount+1; i++ {
		many[fmt.Sprintf("f%03d.yaml", i)] = []byte("version: 1\n")
	}
	tgz, _ = TarGz(many)
	if _, err := ExtractTarGz(dir, tgz); err == nil {
		t.Error("file-count cap must be enforced")
	}
	// Empty archive.
	if _, err := ExtractTarGz(dir, gzTarMemberOnlyHeader()); err == nil {
		t.Error("empty archive must be rejected")
	}
}

func gzTarMember(name string) []byte {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 8})
	_, _ = tw.Write([]byte("version "))
	_ = tw.Close()
	return gz(tarBuf.Bytes())
}

func gzTarMemberOnlyHeader() []byte {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	tw.Close()
	return gz(tarBuf.Bytes())
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}
