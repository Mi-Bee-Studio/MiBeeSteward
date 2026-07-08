package handler

import (
	"net/http"
	"strconv"
	"time"

	"mibee-steward/internal/db"
)

// ChangeLogEntry is one row of the change history, JSON-tagged for the API.
// BeforeData/AfterData are the raw JSON strings stored at detect time
// (before_data = full device snapshot for changed/lost; after_data = the new
// snapshot for added, or a {field: [old,new]} diff map for changed).
type ChangeLogEntry struct {
	ID          int64      `json:"id"`
	AgentID     *string    `json:"agent_id,omitempty"`
	NetworkID   *int64     `json:"network_id,omitempty"`
	ChangeType  string     `json:"change_type"`
	EntityType  string     `json:"entity_type"`
	EntityID    *int64     `json:"entity_id,omitempty"`
	BeforeData  *string    `json:"before_data,omitempty"`
	AfterData   *string    `json:"after_data,omitempty"`
	DetectedAt  time.Time  `json:"detected_at"`
}

// ChangeLogResponse is the paginated change-history payload.
type ChangeLogResponse struct {
	Changes []ChangeLogEntry `json:"changes"`
	Total   int              `json:"total"`
}

// ChangeLogHandler serves the change-history query API.
type ChangeLogHandler struct {
	queries *db.Queries
}

// NewChangeLogHandler constructs the handler.
func NewChangeLogHandler(queries *db.Queries) *ChangeLogHandler {
	return &ChangeLogHandler{queries: queries}
}

// List handles GET /api/v1/changes — paginated change history, newest first.
// Query params (all optional):
//
//	network_id  — filter to one network (0/absent = all networks)
//	change_type — filter to one type (device_added / device_changed / device_lost)
//	entity_type — filter to one entity (device; service/neighbor reserved)
//	limit/offset — pagination (default 50, max 200)
func (h *ChangeLogHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	if offset < 0 {
		offset = 0
	}

	// network_id: parse to a *int64 (nil = all networks).
	var networkID *int64
	if v := q.Get("network_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 {
			networkID = &id
		}
	}
	// The sentinel for "all" is Column1=0 (the (? = 0 OR network_id = ?) clause).
	netSentinel := int64(0)
	if networkID != nil {
		netSentinel = 1
	}
	changeType := q.Get("change_type")
	typeSentinel := ""
	if changeType != "" {
		typeSentinel = "1"
	}
	entityType := q.Get("entity_type")
	entitySentinel := ""
	if entityType != "" {
		entitySentinel = "1"
	}

	rows, err := h.queries.ListChangeLog(r.Context(), db.ListChangeLogParams{
		Column1:    netSentinel,
		NetworkID:  networkID,
		Column3:    typeSentinel,
		ChangeType: changeType,
		Column5:    entitySentinel,
		EntityType: entityType,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list changes")
		return
	}
	total, err := h.queries.CountChangeLog(r.Context(), db.CountChangeLogParams{
		Column1:    netSentinel,
		NetworkID:  networkID,
		Column3:    typeSentinel,
		ChangeType: changeType,
		Column5:    entitySentinel,
		EntityType: entityType,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to count changes")
		return
	}

	out := make([]ChangeLogEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, ChangeLogEntry{
			ID:         row.ID,
			AgentID:    row.AgentID,
			NetworkID:  row.NetworkID,
			ChangeType: row.ChangeType,
			EntityType: row.EntityType,
			EntityID:   row.EntityID,
			BeforeData: row.BeforeData,
			AfterData:  row.AfterData,
			DetectedAt: row.DetectedAt,
		})
	}
	Success(w, ChangeLogResponse{Changes: out, Total: int(total)})
}
