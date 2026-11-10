// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Package discovery implements LAN self-announcement (#729, Scout docs/02 §8
// ecosystem service discovery): so the Scout app's one-shot LAN scan
// recognizes this instance's service type instead of requiring a hand-typed
// address. Three surfaces under one config switch (discovery.*):
//
//   - mDNS advertisement (_mibee-steward._tcp, mdns.go) — the App's primary
//     path;
//   - the public well-known identity endpoint /.well-known/mibee-service
//     (handler wired in internal/api/routes) — the subnet-scan classifier;
//   - the UDP discovery responder (responder.go) — the fallback for
//     multicast-restricted Wi-Fi.
//
// Every surface announces the same minimal identity (stable ID + instance
// name + API port) — the same disclosure posture as /health, deliberately
// nothing more.
package discovery

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// instanceIDFile holds the stable per-installation instance ID, persisted
// next to the SQLite DB. Deliberately a file, NOT a schema change: the
// schema has no in-place upgrade path, and a 32-char ID does not justify
// putting every existing install behind a migration wall.
const instanceIDFile = "instance-id"

// fallbackName is announced when neither config nor OS provides a name.
const fallbackName = "mibee-steward"

// Identity is the stable per-installation identity announced on all three
// discovery surfaces. ID is the App-side bind/merge anchor (Scout docs/02
// §8): it must survive restarts, upgrades, and IP changes.
type Identity struct {
	ID   string // 32 lowercase hex chars (16 random bytes)
	Name string // instance display name (config override → hostname → fallback)
}

// LoadIdentity reads or creates the stable instance ID under dataDir and
// resolves the announced name. A data dir that cannot be written degrades
// to an ephemeral per-process ID with a warn — discovery is optional and
// must never keep the server down (same posture as the SNMP trap receiver);
// the only cost is that App-side bind anchors reset on restart.
func LoadIdentity(dataDir, nameOverride string, log *slog.Logger) Identity {
	id := loadOrCreateID(filepath.Join(dataDir, instanceIDFile), log)
	return Identity{ID: id, Name: resolveName(nameOverride)}
}

// loadOrCreateID reads the persisted ID (validating its shape so a corrupted
// file regenerates instead of poisoning the identity forever) or creates and
// persists a fresh one; a failed write leaves an ephemeral ID behind.
func loadOrCreateID(path string, log *slog.Logger) string {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); validID(s) {
			return s
		}
		log.Warn("discovery: corrupted instance-id file, regenerating", "path", path)
	}

	id := newID()
	if err := os.WriteFile(path, []byte(id), 0o644); err != nil {
		log.Warn("discovery: cannot persist instance-id (identity will be ephemeral per process)",
			"path", path, "error", err)
		return id
	}
	log.Info("discovery: generated stable instance id", "path", path)
	return id
}

// newID returns 16 random bytes as 32 lowercase hex chars.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on healthy systems; panic rather than
		// announce a predictable ID.
		panic(fmt.Sprintf("discovery: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// validID accepts exactly 32 lowercase hex chars.
func validID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// resolveName trims the config override; an empty value falls back to the
// OS hostname, then to a static name. Empty/whitespace is never announced.
func resolveName(nameOverride string) string {
	if s := strings.TrimSpace(nameOverride); s != "" {
		return s
	}
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSpace(h)
	}
	return fallbackName
}
