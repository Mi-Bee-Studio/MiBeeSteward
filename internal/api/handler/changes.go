// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"mibee-steward/internal/authz/scopeql"
	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
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
	dbConn  *sql.DB // raw connection for the scope-restricted list/count
	// (sqlc can't express a variable IN-list, so the closed-mode path builds the
	// WHERE with scopeql.NetworkPredicate and runs it directly).
}

// NewChangeLogHandler constructs the handler. dbConn powers the object-scope
// (closed-mode) list/count; it may be nil when scope is never enforced.
func NewChangeLogHandler(queries *db.Queries, dbConn *sql.DB) *ChangeLogHandler {
	return &ChangeLogHandler{queries: queries, dbConn: dbConn}
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
	// Search: substring across change_type/entity_type. Empty ⇒ no filter.
	searchVal := q.Get("search")

	// Object-level network scope (#138 Phase 2b): closed-mode non-admin callers
	// see only changes on their granted networks. The global path (admin / open
	// mode) keeps the existing sqlc query; the restricted path builds a raw
	// WHERE with scopeql.NetworkPredicate (sqlc can't express a variable IN-list).
	scope := domain.ScopeFromContext(r.Context())
	if !scope.IsGlobal() && h.dbConn != nil {
		out, total, err := h.listScopedChanges(r.Context(), scope, networkID,
			changeType, entityType, searchVal, limit, offset)
		if err != nil {
			Error(w, http.StatusInternalServerError, "failed to list changes")
			return
		}
		Success(w, ChangeLogResponse{Changes: out, Total: int(total)})
		return
	}

	rows, err := h.queries.ListChangeLog(r.Context(), db.ListChangeLogParams{
		Column1:    netSentinel,
		NetworkID:  networkID,
		Column3:    typeSentinel,
		ChangeType: changeType,
		Column5:    entitySentinel,
		EntityType: entityType,
		Column7:    searchVal,
		LOWER:      searchVal,
		LOWER_2:    searchVal,
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
		Column7:    searchVal,
		LOWER:      searchVal,
		LOWER_2:    searchVal,
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

// listScopedChanges runs the scope-restricted change-history query (closed mode).
// It mirrors the ListChangeLog/CountChangeLog sqlc shape exactly (same filters,
// ordering, pagination) but swaps the single-network filter for the caller's
// granted-network IN-list via scopeql.NetworkPredicate. The optional network_id
// param still narrows within the scope (a network_id outside the scope is
// already excluded by the IN-list). Returns the page + total count.
func (h *ChangeLogHandler) listScopedChanges(
	ctx context.Context, scope domain.Scope, networkID *int64,
	changeType, entityType, searchVal string, limit, offset int64,
) ([]ChangeLogEntry, int64, error) {
	netPred, netArgs := scopeql.NetworkPredicate(scope, "")

	typeSentinel := ""
	if changeType != "" {
		typeSentinel = "1"
	}
	entitySentinel := ""
	if entityType != "" {
		entitySentinel = "1"
	}
	searchSentinel := ""
	if searchVal != "" {
		searchSentinel = "1"
	}
	netSentinel := 0
	var netVal int64
	if networkID != nil {
		netSentinel = 1
		netVal = *networkID
	}

	// WHERE common to both the list and the count.
	where := "WHERE " + netPred +
		" AND (? = 0 OR network_id = ?)" +
		" AND (? = '' OR change_type = ?)" +
		" AND (? = '' OR entity_type = ?)" +
		" AND (? = '' OR INSTR(lower(change_type), lower(?)) > 0 OR INSTR(lower(entity_type), lower(?)) > 0)"

	countArgs := make([]any, 0, len(netArgs)+10)
	countArgs = append(countArgs, netArgs...)
	countArgs = append(countArgs, netSentinel, netVal,
		typeSentinel, changeType, entitySentinel, entityType,
		searchSentinel, searchVal, searchVal)

	var total int64
	if err := h.dbConn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM change_log "+where, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := make([]any, 0, len(countArgs)+2)
	listArgs = append(listArgs, countArgs...)
	listArgs = append(listArgs, limit, offset)
	rows, err := h.dbConn.QueryContext(ctx,
		"SELECT id, agent_id, network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at "+
			"FROM change_log "+where+" ORDER BY detected_at DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]ChangeLogEntry, 0)
	for rows.Next() {
		var e ChangeLogEntry
		if err := rows.Scan(&e.ID, &e.AgentID, &e.NetworkID, &e.ChangeType,
			&e.EntityType, &e.EntityID, &e.BeforeData, &e.AfterData, &e.DetectedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
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
	// SSE headers: text/event-stream, no buffering, long-lived connection.
	// These MUST be set before any Flush/WriteHeader — Go's net/http commits
	// the status line + headers on the first write or Flush, snapshotting the
	// header map at that instant. A Flush before these Set() calls (the old
	// capability check) committed 200 with an empty Content-Type, so the
	// browser aborted the EventSource to CLOSED and the UI showed a permanent
	// "已断开" banner (#195). The Flush below now both verifies streaming
	// support AND sends the headers in the correct order.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	// Use http.ResponseController so Flush traverses middleware wrappers
	// (metricsResponseWriter / responseWriter) via their Unwrap() method to
	// reach the server's real http.Flusher. A direct w.(http.Flusher) cast
	// fails because those wrappers don't implement Flusher themselves, which
	// previously made this endpoint return 500 "streaming not supported".
	rc := http.NewResponseController(w)

	// SSE connections are long-lived; the server's WriteTimeout (default 5m,
	// an absolute deadline from end-of-header-read) would otherwise kill every
	// stream at 5 minutes. Clear the per-connection write deadline so the
	// keepalive loop below governs liveness instead. Best-effort: if the
	// underlying connection doesn't support SetWriteDeadline this is a no-op.
	_ = rc.SetWriteDeadline(time.Time{})

	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		// Streaming genuinely unsupported by the transport (not just middleware
		// wrappers) — nothing we can do; headers are already committed so we
		// cannot switch to a JSON error. Log and end the request.
		h.logger.Warn("change watch: streaming not supported", "error", err)
		return
	}

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

	// Send an initial comment immediately so the client knows the stream is
	// live (the next line otherwise waits up to the 15s keepalive). Also gives
	// downstream consumers — and tests — a fast connection-established signal.
	if _, err := fmt.Fprintf(w, ": connected\n\n"); err != nil {
		return
	}
	rc.Flush()

	ctx := r.Context()
	// Object-level network scope (#138 Phase 2b): a restricted caller's stream
	// must not leak change events from networks they hold no grant for. Events
	// are filtered per-row here (the Watcher fans out to every subscriber).
	scope := domain.ScopeFromContext(r.Context())
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
			// Restricted scope: drop events whose network is out of scope (a
			// change with no network_id is hidden — conservative for isolation).
			if !scope.IsGlobal() && (row.NetworkID == nil || !scope.AllowsNetwork(*row.NetworkID)) {
				continue
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
