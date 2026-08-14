// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/authz/scoperesolver"
)

// NetworkGrantHandler is the admin management surface for object-level network
// scope (#138 Phase 2/3): create/list/delete user↔network grants. All routes are
// gated by CapUserManage (admin-only). Each mutation invalidates the scope
// resolver's cache for the affected user so the change takes effect immediately.
type NetworkGrantHandler struct {
	db       *sql.DB
	resolver *scoperesolver.Resolver
}

func NewNetworkGrantHandler(db *sql.DB, resolver *scoperesolver.Resolver) *NetworkGrantHandler {
	return &NetworkGrantHandler{db: db, resolver: resolver}
}

type networkGrantRequest struct {
	UserID    int64 `json:"user_id"`
	NetworkID int64 `json:"network_id"`
}

type networkGrantResponse struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	Username    string `json:"username,omitempty"`
	NetworkID   int64  `json:"network_id"`
	NetworkName string `json:"network_name,omitempty"`
	GrantedAt   string `json:"granted_at"`
}

// Create handles POST /api/v1/network-grants {user_id, network_id}. Validates
// that both the user and network exist (otherwise 400) so grants can't dangle.
// A duplicate (user,network) returns 409.
func (h *NetworkGrantHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req networkGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID <= 0 || req.NetworkID <= 0 {
		Error(w, http.StatusBadRequest, "user_id and network_id are required")
		return
	}
	if !rowExists(r.Context(), h.db, `SELECT 1 FROM users WHERE id = ?`, req.UserID) {
		Error(w, http.StatusBadRequest, "user not found")
		return
	}
	if !rowExists(r.Context(), h.db, `SELECT 1 FROM networks WHERE id = ?`, req.NetworkID) {
		Error(w, http.StatusBadRequest, "network not found")
		return
	}
	id, err := scoperesolver.Create(r.Context(), h.db, req.UserID, req.NetworkID)
	if err != nil {
		if isUniqueConstraintErr(err) {
			Error(w, http.StatusConflict, "grant already exists")
			return
		}
		slog.Error("network grant: create", "error", err)
		Error(w, http.StatusInternalServerError, "failed to create grant")
		return
	}
	h.resolver.Invalidate(req.UserID)
	Created(w, networkGrantResponse{ID: id, UserID: req.UserID, NetworkID: req.NetworkID})
}

// List handles GET /api/v1/network-grants (admin view of every grant, joined to
// username + network name). Paginated by limit/offset.
func (h *NetworkGrantHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	grants, total, err := scoperesolver.ListAll(r.Context(), h.db, int(limit), int(offset))
	if err != nil {
		slog.Error("network grant: list", "error", err)
		Error(w, http.StatusInternalServerError, "failed to list grants")
		return
	}
	out := make([]networkGrantResponse, 0, len(grants))
	for _, g := range grants {
		out = append(out, networkGrantResponse{
			ID: g.ID, UserID: g.UserID, Username: g.Username,
			NetworkID: g.NetworkID, NetworkName: g.NetworkName, GrantedAt: g.GrantedAt,
		})
	}
	Success(w, map[string]any{"grants": out, "total": total})
}

// ListByUser handles GET /api/v1/users/{id}/network-grants — the networks a user
// is granted (used by the user-edit form to show/edit scope).
func (h *NetworkGrantHandler) ListByUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || userID <= 0 {
		Error(w, http.StatusBadRequest, "invalid user id")
		return
	}
	grants, err := scoperesolver.ListByUser(r.Context(), h.db, userID)
	if err != nil {
		slog.Error("network grant: list for user", "error", err)
		Error(w, http.StatusInternalServerError, "failed to list grants")
		return
	}
	out := make([]networkGrantResponse, 0, len(grants))
	for _, g := range grants {
		out = append(out, networkGrantResponse{ID: g.ID, UserID: g.UserID, NetworkID: g.NetworkID, GrantedAt: g.GrantedAt})
	}
	Success(w, map[string]any{"grants": out, "total": len(out)})
}

// Delete handles DELETE /api/v1/network-grants/{id}. Looks up the grant first so
// the resolver can be invalidated for the right user.
func (h *NetworkGrantHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid grant id")
		return
	}
	var userID int64
	err = h.db.QueryRowContext(r.Context(),
		`SELECT user_id FROM user_network_grants WHERE id = ?`, id).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		Error(w, http.StatusNotFound, "grant not found")
		return
	}
	if err != nil {
		slog.Error("network grant: lookup", "error", err)
		Error(w, http.StatusInternalServerError, "failed to delete grant")
		return
	}
	ok, err := scoperesolver.Delete(r.Context(), h.db, id)
	if err != nil {
		slog.Error("network grant: delete", "error", err)
		Error(w, http.StatusInternalServerError, "failed to delete grant")
		return
	}
	if !ok {
		Error(w, http.StatusNotFound, "grant not found")
		return
	}
	h.resolver.Invalidate(userID)
	w.WriteHeader(http.StatusNoContent)
}

// rowExists reports whether a scalar SELECT-y query returns at least one row.
// Used for existence checks (user/network) before inserting a grant.
func rowExists(ctx context.Context, db *sql.DB, query string, args ...any) bool {
	var tmp any
	err := db.QueryRowContext(ctx, query, args...).Scan(&tmp)
	return err == nil
}
