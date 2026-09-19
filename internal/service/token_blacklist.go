// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"sync"
	"time"
)

// TokenBlacklist stores revoked JWT token IDs, expiring them lazily on read.
//
// There is deliberately NO background cleanup goroutine: expired entries are
// dropped by IsBlacklisted when it touches them, and the map is bounded by the
// number of tokens that ever logged out (each entry dies with its token's own
// JWT expiry, so a revocation outlives the token it revokes by design). The
// previous 10-minute sweeper goroutine leaked on every NewRouter call — its
// StopCleanup had no production callers, and calling it twice panicked on
// double-close. Lazy expiry deletes that entire lifecycle.
type TokenBlacklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti -> expiry time
}

func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		entries: make(map[string]time.Time),
	}
}

// Add adds a token JTI to the blacklist with the given TTL (token's remaining lifetime).
func (b *TokenBlacklist) Add(jti string, ttl time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[jti] = time.Now().Add(ttl)
}

// IsBlacklisted reports whether a token JTI is revoked and not yet expired.
// An expired entry is deleted on sight (lazy expiry) so the map self-cleans
// under normal traffic without a sweeper goroutine.
func (b *TokenBlacklist) IsBlacklisted(jti string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	expiry, exists := b.entries[jti]
	if !exists {
		return false
	}
	if !time.Now().Before(expiry) {
		delete(b.entries, jti)
		return false
	}
	return true
}
