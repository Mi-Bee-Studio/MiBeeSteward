// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.

// Package fpsync defines the fingerprint-corpus distribution format shared
// by the center (producer) and agents (consumer): a set of *.yaml rule files,
// a content-addressed revision hash, and a deterministic tar.gz envelope.
//
// The corpus-update loop this enables: drop/edit YAML in the center's
// scanner.fingerprint_path (or ship a new embedded corpus in a center
// binary), agents pick it up over GET /api/v1/agents/fingerprints, validate
// it locally (the rule engine's load-time validation), swap it in, and
// re-exec — no agent binary rebuild involved.
package fpsync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Limits the extractor enforces so a corrupt or hostile archive can't exhaust
// disk or wedge the agent. The shipped corpus is ~1.2 MB across 8 files;
// generous headroom allows multi-year corpus growth.
const (
	MaxArchiveBytes = 16 << 20 // 16 MiB
	MaxFileCount    = 64
	MaxFileBytes    = 4 << 20 // 4 MiB per YAML file
)

// ReadCorpusDir loads every *.yaml file in dir into a name→content map.
// A missing dir returns (nil, nil) so callers can fall back (embedded).
func ReadCorpusDir(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, ent := range entries {
		if ent.IsDir() || strings.ToLower(filepath.Ext(ent.Name())) != ".yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", ent.Name(), err)
		}
		files[ent.Name()] = b
	}
	return files, nil
}

// Hash computes the corpus revision: SHA-256 over the sorted
// (name, NUL, content, NUL) pairs. Purely content-addressed — mtime and
// file-order changes never bump the revision, so agents don't churn on
// restarts or rsync.
func Hash(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write(files[n])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TarGz packs the corpus into a deterministic tar.gz (sorted names, zeroed
// metadata) so identical corpora produce byte-identical envelopes.
func TarGz(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{
			Name: n, Mode: 0o644, Size: int64(len(files[n])),
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExtractTarGz unpacks a corpus envelope into dir (created if needed) and
// returns the extracted file names. Defense in depth: only flat *.yaml
// entries, sanitized names, per-file and total caps, decompression-bomb
// bound. Anything unexpected is a hard error — the whole archive is
// rejected, never partially applied.
func ExtractTarGz(dir string, archive []byte) ([]string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer zr.Close()
	zr.Multistream(false) // single member; io.LimitReader above already bounds input

	tr := tar.NewReader(io.LimitReader(zr, MaxArchiveBytes))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var names []string
	total := int64(0)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("entry %q: only regular files allowed", hdr.Name)
		}
		// The distribution format is FLAT: a member name carrying any path
		// shape (dirs, traversal, absolute) is malformed, not flattened —
		// reject it so nobody grows to rely on silent rewriting.
		if filepath.Base(hdr.Name) != hdr.Name || hdr.Name == "." || hdr.Name == ".." {
			return nil, fmt.Errorf("entry %q: flat file names only", hdr.Name)
		}
		name := hdr.Name
		if strings.ToLower(filepath.Ext(name)) != ".yaml" {
			return nil, fmt.Errorf("entry %q: only .yaml files allowed", hdr.Name)
		}
		if hdr.Size > MaxFileBytes {
			return nil, fmt.Errorf("entry %q: exceeds %d bytes", name, MaxFileBytes)
		}
		if len(names) >= MaxFileCount {
			return nil, fmt.Errorf("more than %d files", MaxFileCount)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", name, err)
		}
		total += int64(len(body))
		if total > MaxArchiveBytes {
			return nil, fmt.Errorf("archive exceeds %d bytes", MaxArchiveBytes)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, errors.New("archive contains no yaml files")
	}
	return names, nil
}
