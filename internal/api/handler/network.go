package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
)

// errNetworkNotFound signals an UPDATE/DELETE targeted a non-existent network.
var errNetworkNotFound = errors.New("network not found")

// NetworkHandler serves the network registry (the logical networks agents
// discover for). Used by the frontend to populate the device-list network
// filter, the change-history network filter, and the Networks admin page.
type NetworkHandler struct {
	queries *db.Queries
	conn    db.DBTX // raw connection for UPDATE (sqlc truncation workaround)
}

// NewNetworkHandler constructs the handler. conn is the shared *sql.DB used
// for the raw UPDATE statement (sqlc v1.31.1 truncates the generated string
// for UpdateNetwork's multi-bind shape).
func NewNetworkHandler(queries *db.Queries, conn db.DBTX) *NetworkHandler {
	return &NetworkHandler{queries: queries, conn: conn}
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
	if strings.TrimSpace(req.Name) == "" {
		Error(w, http.StatusBadRequest, "name is required")
		return
	}
	net, err := h.queries.CreateNetwork(r.Context(), db.CreateNetworkParams{
		Name: strings.TrimSpace(req.Name),
		Cidr: trimPtr(req.Cidr),
		Site: trimPtr(req.Site),
	})
	if err != nil {
		// networks.name is UNIQUE — a duplicate surfaces as a constraint error.
		if isUniqueConstraintErr(err) {
			Error(w, http.StatusConflict, "a network with this name already exists")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to create network")
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
	if strings.TrimSpace(req.Name) == "" {
		Error(w, http.StatusBadRequest, "name is required")
		return
	}
	net, err := h.UpdateNetworkRaw(r.Context(), id, strings.TrimSpace(req.Name), trimPtr(req.Cidr), trimPtr(req.Site))
	if err != nil {
		if errors.Is(err, errNetworkNotFound) {
			Error(w, http.StatusNotFound, "network not found")
			return
		}
		if isUniqueConstraintErr(err) {
			Error(w, http.StatusConflict, "a network with this name already exists")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update network")
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
	if err := h.queries.DeleteNetwork(r.Context(), id); err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete network")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UpdateNetworkRaw runs the UPDATE via raw database/sql and reads the updated
// row back via GetNetwork. This works around sqlc v1.31.1 truncating the
// generated query string for this multi-bind UPDATE shape (drops the trailing
// `?`). The SQL is a bind-parameter statement, so it's safe from the SQLite
// empty-string-literal truncation bug noted in networks.sql (that only affects
// inlined literals).
func (h *NetworkHandler) UpdateNetworkRaw(ctx context.Context, id int64, name string, cidr, site *string) (db.Network, error) {
	const stmt = `UPDATE networks SET name = ?, cidr = ?, site = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	res, err := h.conn.ExecContext(ctx, stmt, name, cidr, site, id)
	if err != nil {
		return db.Network{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return db.Network{}, errNetworkNotFound
	}
	return h.queries.GetNetwork(ctx, id)
}

// trimPtr returns a pointer to the trimmed value, or nil if the input is nil
// or empty-after-trim (so empty strings aren't stored as " ").
func trimPtr(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	if t == "" {
		return nil
	}
	return &t
}

// isUniqueConstraintErr reports whether err is a SQLite UNIQUE constraint
// violation (modernc.org/sqlite returns "UNIQUE constraint failed: ...").
func isUniqueConstraintErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
