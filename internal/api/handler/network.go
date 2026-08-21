// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service"
)

// NetworkHandler serves the network registry (the logical networks agents
// discover for). Used by the frontend to populate the device-list network
// filter, the change-history network filter, and the Networks admin page.
// Mutations go through service.NetworkService (#240 — this handler was one of
// the four grandfathered charter-debt direct-DB writers); List is a read
// passthrough on *db.Queries.
type NetworkHandler struct {
	queries *db.Queries
	svc     *service.NetworkService
}

// NewNetworkHandler constructs the handler.
func NewNetworkHandler(queries *db.Queries, svc *service.NetworkService) *NetworkHandler {
	return &NetworkHandler{queries: queries, svc: svc}
}

// List handles GET /api/v1/networks — all networks, ordered by id.
func (h *NetworkHandler) List(w http.ResponseWriter, r *http.Request) {
	nets, err := h.queries.ListNetworks(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list networks")
		return
	}
	Success(w, nets)
}

// Get handles GET /api/v1/networks/{id} — one network by id. Previously only
// PUT/DELETE were registered, so a GET fell through to the method-not-allowed
// (405); reading one network required pulling the whole list (#257).
func (h *NetworkHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid network ID")
		return
	}
	net, err := h.queries.GetNetwork(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Error(w, http.StatusNotFound, "network not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get network")
		return
	}
	Success(w, net)
}

// createNetworkRequest is the body for POST /api/v1/networks.
type createNetworkRequest struct {
	Name string  `json:"name"` // required, non-empty
	Cidr *string `json:"cidr"` // optional, advisory (no strict validation)
	Site *string `json:"site"` // optional, advisory (branch/datacenter/cloud)
}

// Create handles POST /api/v1/networks — register a new logical network.
// This is the admin path for defining the remote networks that agents discover
// for (the center's own network is auto-resolved at startup via resolveNetworkID).
func (h *NetworkHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	net, err := h.svc.Create(r.Context(), service.NetworkInput{Name: req.Name, Cidr: req.Cidr, Site: req.Site})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNetworkNameRequired):
			Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, service.ErrNetworkNameTaken):
			Error(w, http.StatusConflict, err.Error())
		default:
			Error(w, http.StatusInternalServerError, "failed to create network")
		}
		return
	}
	Created(w, net)
}

// updateNetworkRequest is the body for PUT /api/v1/networks/{id}.
type updateNetworkRequest struct {
	Name string  `json:"name"` // required
	Cidr *string `json:"cidr"`
	Site *string `json:"site"`
}

// Update handles PUT /api/v1/networks/{id} — edit name/cidr/site.
// The agent_id is intentionally NOT editable here (owned by the agent-token flow).
func (h *NetworkHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req updateNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	net, err := h.svc.Update(r.Context(), id, service.NetworkInput{Name: req.Name, Cidr: req.Cidr, Site: req.Site})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNetworkNameRequired):
			Error(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, service.ErrNetworkNotFound):
			Error(w, http.StatusNotFound, err.Error())
		case errors.Is(err, service.ErrNetworkNameTaken):
			Error(w, http.StatusConflict, err.Error())
		default:
			Error(w, http.StatusInternalServerError, "failed to update network")
		}
		return
	}
	Success(w, net)
}

// Delete handles DELETE /api/v1/networks/{id} — remove a logical network.
// FK references are ON DELETE SET NULL (devices/vlans/agent_tokens/change_log)
// or CASCADE (subnets/scan_snapshots), so devices keep their rows with a NULL
// network_id rather than vanishing.
func (h *NetworkHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		if errors.Is(err, service.ErrNetworkNotFound) {
			Error(w, http.StatusNotFound, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete network")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
