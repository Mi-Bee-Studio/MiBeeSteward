package handler

import (
	"net/http"

	"mibee-steward/internal/db"
)

// NetworkHandler serves the network registry (the logical networks agents
// discover for). Used by the frontend to populate the device-list network
// filter and the change-history network filter.
type NetworkHandler struct {
	queries *db.Queries
}

// NewNetworkHandler constructs the handler.
func NewNetworkHandler(queries *db.Queries) *NetworkHandler {
	return &NetworkHandler{queries: queries}
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
