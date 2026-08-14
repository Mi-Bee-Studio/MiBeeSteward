// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package scoperesolver

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"mibee-steward/internal/domain"
)

const cacheTTL = 30 * time.Second

// Resolver caches each user's granted network_ids for cacheTTL, then re-reads.
// It resolves a (userID, role) pair to a domain.Scope:
//   - admin role → Global (bypasses scope),
//   - open mode → Global (non-admin sees everything; default, no behavior change),
//   - closed mode + non-admin → Restricted(granted network_ids); no grants → empty
//     (sees nothing).
//
// A nil *Resolver resolves to Global everywhere (scope disabled / not wired).
type Resolver struct {
	db    *sql.DB
	mode  domain.ScopeMode
	cache map[int64]cacheEntry
	mu    sync.Mutex
}

type cacheEntry struct {
	ids []int64
	at  time.Time
}

// New constructs a resolver. mode is the canonical rbac.scope_default
// (domain.ScopeModeOpen / ScopeModeClosed).
func New(db *sql.DB, mode domain.ScopeMode) *Resolver {
	return &Resolver{db: db, mode: mode, cache: make(map[int64]cacheEntry)}
}

// Mode reports the configured scope mode.
func (r *Resolver) Mode() domain.ScopeMode {
	if r == nil {
		return domain.ScopeModeOpen
	}
	return r.mode
}

// Resolve returns the effective network scope for a user. It never returns an
// error: on DB failure it fails OPEN (Global) so a transient DB hiccup cannot
// lock users out of inventory (fail-safe for availability; logged by caller if
// needed). Admin and open-mode always short-circuit without touching the DB.
func (r *Resolver) Resolve(ctx context.Context, userID int64, role domain.UserRole) domain.Scope {
	if r == nil {
		return domain.Scope{Global: true}
	}
	// Admin always bypasses object scope.
	if role == domain.RoleAdmin {
		return domain.Scope{Global: true}
	}
	// Open mode: no enforcement (default; preserves existing single-team installs).
	if r.mode != domain.ScopeModeClosed {
		return domain.Scope{Global: true}
	}
	// Closed mode + non-admin: restrict to granted networks.
	ids, ok := r.cached(userID)
	if !ok {
		var err error
		ids, err = NetworkIDsByUser(ctx, r.db, userID)
		if err != nil {
			// Fail open on DB error (availability over strictness); cache nothing.
			return domain.Scope{Global: true}
		}
		r.store(userID, ids)
	}
	return domain.Scope{Global: false, NetworkIDs: ids}
}

func (r *Resolver) cached(userID int64) ([]int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[userID]; ok && time.Since(e.at) < cacheTTL {
		return e.ids, true
	}
	return nil, false
}

func (r *Resolver) store(userID int64, ids []int64) {
	r.mu.Lock()
	r.cache[userID] = cacheEntry{ids: ids, at: time.Now()}
	r.mu.Unlock()
}

// Invalidate drops the cached scope for one user. The grants management handler
// MUST call this after any create/delete affecting that user.
func (r *Resolver) Invalidate(userID int64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.cache, userID)
	r.mu.Unlock()
}

// InvalidateAll drops every cached scope (e.g. on a scope-mode change or bulk
// grant operation).
func (r *Resolver) InvalidateAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cache = make(map[int64]cacheEntry)
	r.mu.Unlock()
}
