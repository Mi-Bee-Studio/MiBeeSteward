// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL license does not accommodate; see LICENSE-COMMERCIAL.md.

package classify

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	fp "github.com/Mi-Bee-Studio/mibee-fingerprints-go"
)

// The embedded copy of the fingerprint corpus (configs/fingerprints/ synced
// here by `make sync-fingerprints`). This is a STRICT SUPERSET of the
// standalone fingerprint library's own embedded rules: it additionally ships
// the in-repo corpora the external library doesn't (iot-identity.yaml #361,
// mdns-ssdp.yaml #365) — which is exactly why the ENGINE must load from THIS
// copy, not the library's LoadEmbeddedDefaults: field-found on R68S that the
// zero-config fallback silently lacked the Mijia/mDNS rules, so they never
// fired on real deployments (#377).
//
//go:embed all:fingerprint-assets
var embeddedAssets embed.FS

// LoadEmbeddedRules loads the synced corpus embedded in this package into rc
// (replacing anything rc holds). The files are materialized into a scratch
// directory for LoadFromDir and removed immediately after — the classifier
// compiles eagerly, nothing references the directory afterwards.
func LoadEmbeddedRules(rc *fp.RuleClassifier) error {
	if rc == nil {
		return nil
	}
	dir, err := os.MkdirTemp("", "mibee-fp-*")
	if err != nil {
		return fmt.Errorf("scratch dir: %w", err)
	}
	defer os.RemoveAll(dir)

	entries, err := embeddedAssets.ReadDir("fingerprint-assets")
	if err != nil {
		return fmt.Errorf("read embedded assets: %w", err)
	}
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".yaml" {
			continue
		}
		body, err := embeddedAssets.ReadFile("fingerprint-assets/" + ent.Name())
		if err != nil {
			return fmt.Errorf("read %s: %w", ent.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, ent.Name()), body, 0o644); err != nil {
			return fmt.Errorf("stage %s: %w", ent.Name(), err)
		}
	}
	if err := rc.LoadFromDir(dir); err != nil {
		return fmt.Errorf("load embedded corpus: %w", err)
	}
	if !rc.Loaded() {
		return fmt.Errorf("embedded corpus loaded zero rules")
	}
	return nil
}
