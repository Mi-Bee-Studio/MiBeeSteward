package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
)

// ChangeLogEntry is one row of the change history, JSON-tagged for the API.
// BeforeData/AfterData are the raw JSON strings stored at detect time
// (before_data = full device snapshot for changed/lost; after_data = the new
// snapshot for added, or a {field: [old,new]} diff map for changed).
type ChangeLogEntry struct {
	ID         int64     `json:"id"`
	AgentID    *string   `json:"agent_id,omitempty"`
	NetworkID  *int64    `json:"network_id,omitempty"`
	ChangeType string    `json:"change_type"`
	EntityType string    `json:"entity_type"`
	EntityID   *int64    `json:"entity_id,omitempty"`
	BeforeData *string   `json:"before_data,omitempty"`
	AfterData  *string   `json:"after_data,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
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

// ChangeWatchHandler streams change events to clients via Server-Sent Events
// (SSE). It subscribes to the in-process Watcher and forwards each change_log
// row as an SSE "change" event. This is the external consumer for the Watcher
// (architecture-future.md §8) — a dashboard or external integration can listen
// for real-time device_added/changed/lost events without polling.
//
// Connection lifecycle: the stream stays open until the client disconnects
// (ctx.Done) or the server shuts down. A heartbeat comment (":keepalive") is
// sent every 15s so proxies don't idle-timeout the connection. The Watcher
// drops events to a full subscriber buffer (best-effort; the client can
// backfill from GET /changes).
type ChangeWatchHandler struct {
	watcher *changedetect.Watcher
	logger  *slog.Logger
}

// NewChangeWatchHandler constructs the SSE handler. watcher is the center's
// in-process change-event fan-out (the same one DBRecorder pushes to).
func NewChangeWatchHandler(watcher *changedetect.Watcher, logger *slog.Logger) *ChangeWatchHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &ChangeWatchHandler{watcher: watcher, logger: logger}
}

// Watch handles GET /api/v1/changes/watch (SSE stream).
func (h *ChangeWatchHandler) Watch(w http.ResponseWriter, r *http.Request) {
	if h.watcher == nil {
		Error(w, http.StatusServiceUnavailable, "change watcher not initialized")
		return
	}
	// Use http.ResponseController so Flush traverses middleware wrappers
	// (metricsResponseWriter / responseWriter) via their Unwrap() method to
	// reach the server's real http.Flusher. A direct w.(http.Flusher) cast
	// fails because those wrappers don't implement Flusher themselves, which
	// previously made this endpoint return 500 "streaming not supported".
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		Error(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// SSE headers: text/event-stream, no buffering, long-lived connection.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.WriteHeader(http.StatusOK)
	rc.Flush()

	// Subscribe to the Watcher; unsubscribe + drain on exit to avoid leaking
	// the channel (a dropped subscriber would buffer-overflow the Watcher).
	sub := h.watcher.Subscribe()
	defer func() {
		h.watcher.Unsubscribe(sub)
		// Drain any remaining events so the channel isn't GC-blocked.
		for evt := range sub {
			_ = evt // discard; iterating to close is the point
		}
	}()

	// Keepalive ticker: send an SSE comment every 15s so idle proxies/CDNs
	// don't close the connection between events.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			// Client disconnected.
			return
		case <-ticker.C:
			// SSE comment line (ignored by EventSource clients, keeps connection alive).
			if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
				return
			}
			rc.Flush()
		case row, ok := <-sub:
			if !ok {
				// Channel closed (server shutting down).
				return
			}
			data, err := json.Marshal(ChangeLogEntry{
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
			if err != nil {
				h.logger.Warn("change watch: marshal failed", "change_id", row.ID, "error", err)
				continue
			}
			// SSE event: "event: change\ndata: {json}\n\n"
			if _, err := fmt.Fprintf(w, "event: change\ndata: %s\n\n", data); err != nil {
				return // write failed — client likely gone
			}
			rc.Flush()
		}
	}
}
