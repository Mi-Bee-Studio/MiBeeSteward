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
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// ScannerResultHandler handles HTTP requests for scan result and run queries.
type ScannerResultHandler struct {
	queries *db.Queries
	conn    db.DBTX
	// conn is the raw connection used by listResultsSorted — sqlc can't express
	// the dynamic ORDER BY the sort-aware list needs, so that one query is raw
	// SQL with a whitelist-controlled column (mirrors repository/device.go).
}

// NewScannerResultHandler creates a new ScannerResultHandler.
func NewScannerResultHandler(queries *db.Queries, conn db.DBTX) *ScannerResultHandler {
	return &ScannerResultHandler{queries: queries, conn: conn}
}

// scanResultSortWhitelist maps a client-supplied sort token to the real column
// (or SQL expression) used in ORDER BY. Any token not in this map falls back to
// "scanned_at". This is the SQL-injection guard: only these literals ever reach
// ORDER BY, never raw user input (mirrors repository/device.go sortWhitelist).
var scanResultSortWhitelist = map[string]string{
	"ip":     "ip",
	"status": "alive",                    // the "Status" column reflects the alive flag
	"ports":  "json_array_length(ports)", // the "Ports Count" column renders ports.length
}

// ListResults handles GET /api/v1/scanner/results
func (h *ScannerResultHandler) ListResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var taskID int64
	var ipFilter string
	if q.Get("task_id") != "" {
		taskID, _ = strconv.ParseInt(q.Get("task_id"), 10, 64)
	}
	if q.Get("ip") != "" {
		ipFilter = q.Get("ip")
	}
	// alive filter: "1" ⇒ only alive hosts, "0" ⇒ only dead, absent ⇒ both.
	// Encoded as a sentinel (-1 = no filter) for the SQL `(? < 0 OR alive = ?)`.
	aliveSentinel := int64(-1)
	aliveVal := int64(0)
	switch q.Get("alive") {
	case "1", "true":
		aliveSentinel = 1
		aliveVal = 1
	case "0", "false":
		aliveSentinel = 1
		aliveVal = 0
	}

	// Server-side sort. With no sort token the query keeps its default
	// (scanned_at DESC) via the sqlc ListScanResults path — zero behavior
	// change. With a sort token we route through listResultsSorted (raw SQL),
	// which sorts the WHOLE filtered set before LIMIT/OFFSET, so a header click
	// reorders globally rather than just the visible page slice (#55).
	sortBy := q.Get("sort")
	order := q.Get("order")

	var (
		results []db.ScanResult
		err     error
	)
	if sortBy != "" {
		results, err = h.listResultsSorted(r.Context(), taskID, ipFilter, aliveSentinel, aliveVal, sortBy, order, limit, offset)
	} else {
		results, err = h.queries.ListScanResults(r.Context(), db.ListScanResultsParams{
			Column1: taskID,
			TaskID:  taskID,
			Column3: ipFilter,
			Ip:      ipFilter,
			Column5: aliveSentinel,
			Alive:   aliveVal,
			Limit:   limit,
			Offset:  offset,
		})
	}
	if err != nil {
		slog.Error("ListScanResults failed", "task_id", taskID, "ip", ipFilter, "alive", q.Get("alive"), "sort", sortBy, "order", order, "limit", limit, "offset", offset, "error", err)
		Error(w, http.StatusInternalServerError, "failed to list scan results")
		return
	}

	if results == nil {
		results = []db.ScanResult{}
	}

	// CountScanResults now mirrors the same WHERE (task_id + ip + alive) so the
	// page total reflects the active filters instead of the whole task.
	total, err := h.queries.CountScanResults(r.Context(), db.CountScanResultsParams{
		Column1: taskID,
		TaskID:  taskID,
		Column3: ipFilter,
		Ip:      ipFilter,
		Column5: aliveSentinel,
		Alive:   aliveVal,
	})
	if err != nil {
		slog.Error("CountScanResults failed", "task_id", taskID, "error", err)
		Error(w, http.StatusInternalServerError, "failed to count scan results")
		return
	}

	resp := make([]domain.ScanResultResponse, 0, len(results))
	for _, r := range results {
		resp = append(resp, toScanResultResponse(r))
	}

	Success(w, domain.ScanResultListResponse{
		Results: resp,
		Total:   int(total),
	})
}

// listResultsSorted runs the same WHERE/LIMIT/OFFSET as ListScanResults but
// with a whitelist-controlled ORDER BY, so a sort applies across the whole
// filtered set (not just the visible page slice). sqlc can't express the
// dynamic ORDER BY, hence the raw SQL — the column is resolved from
// scanResultSortWhitelist (never interpolated raw from user input), and every
// user value (task_id/ip/alive/limit/offset) is still bound as a `?` param.
// The SELECT column order MUST match db.ScanResult's Scan order (see
// ListScanResults in internal/db/scan_results.sql.go).
func (h *ScannerResultHandler) listResultsSorted(
	ctx context.Context,
	taskID int64, ipFilter string, aliveSentinel, aliveVal int64,
	sortBy, order string, limit, offset int64,
) ([]db.ScanResult, error) {
	col := scanResultSortWhitelist[sortBy]
	if col == "" {
		col = "scanned_at"
	}
	dir := "ASC"
	if order == "desc" {
		dir = "DESC"
	}

	query := `SELECT id, task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data, scanned_at
		FROM scan_results
		WHERE (? = 0 OR task_id = ?)
		  AND (? = '' OR ip LIKE ?)
		  AND (? < 0 OR alive = ?)
		ORDER BY ` + col + " " + dir + `
		LIMIT ? OFFSET ?`

	rows, err := h.conn.QueryContext(ctx, query,
		taskID, taskID,
		ipFilter, ipFilter,
		aliveSentinel, aliveVal,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []db.ScanResult{}
	for rows.Next() {
		var i db.ScanResult
		if err := rows.Scan(
			&i.ID,
			&i.TaskID,
			&i.RunID,
			&i.Ip,
			&i.Alive,
			&i.RttMs,
			&i.Ports,
			&i.Services,
			&i.SnmpData,
			&i.PrometheusDetected,
			&i.PrometheusUrl,
			&i.NodeExporterDetected,
			&i.NodeExporterUrl,
			&i.NodeExporterData,
			&i.ScannedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	return items, rows.Err()
}

// GetResult handles GET /api/v1/scanner/results/{id}
func (h *ScannerResultHandler) GetResult(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	result, err := h.queries.GetScanResult(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Error(w, http.StatusNotFound, "scan result not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get scan result")
		return
	}

	Success(w, toScanResultResponse(result))
}

// ListRuns handles GET /api/v1/scanner/runs
func (h *ScannerResultHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	var taskID int64
	if q.Get("task_id") != "" {
		taskID, _ = strconv.ParseInt(q.Get("task_id"), 10, 64)
	}

	runs, err := h.queries.ListScanTaskRuns(r.Context(), db.ListScanTaskRunsParams{
		Column1: taskID,
		TaskID:  taskID,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list scan task runs")
		return
	}

	if runs == nil {
		runs = []db.ScanTaskRun{}
	}

	total, err := h.queries.CountScanTaskRuns(r.Context(), db.CountScanTaskRunsParams{
		Column1: taskID,
		TaskID:  taskID,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to count scan task runs")
		return
	}

	resp := make([]domain.ScanRunResponse, 0, len(runs))
	for _, run := range runs {
		resp = append(resp, toScanRunResponse(run))
	}

	Success(w, domain.ScanRunListResponse{
		Runs:  resp,
		Total: int(total),
	})
}

// GetRun handles GET /api/v1/scanner/runs/{id}
func (h *ScannerResultHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	run, err := h.queries.GetScanTaskRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Error(w, http.StatusNotFound, "scan task run not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get scan task run")
		return
	}

	Success(w, toScanRunResponse(run))
}

// BulkDeleteResults handles DELETE /api/v1/scanner/results
func (h *ScannerResultHandler) BulkDeleteResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	beforeDate := q.Get("before_date")
	if beforeDate == "" {
		Error(w, http.StatusBadRequest, "before_date query parameter is required (ISO 8601 format)")
		return
	}

	parsed, err := time.Parse(time.RFC3339, beforeDate)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid before_date format, use ISO 8601")
		return
	}

	// Calculate days from now to the given date
	days := int(time.Since(parsed).Hours() / 24)
	if days <= 0 {
		Error(w, http.StatusBadRequest, "before_date must be in the past")
		return
	}

	daysStr := strconv.Itoa(days)
	affected, err := h.queries.DeleteScanResultsOlderThan(r.Context(), &daysStr)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete scan results")
		return
	}

	Success(w, map[string]interface{}{
		"deleted": affected,
	})
}

// ExportScanResults handles GET /api/v1/scanner/results/export?task_id=X
// Returns CSV with columns: IP, Alive, RTT_ms, SNMP_Name, SNMP_Descr, Brand, Type, Location, Ports, Services
func (h *ScannerResultHandler) ExportScanResults(w http.ResponseWriter, r *http.Request) {
	taskIDStr := r.URL.Query().Get("task_id")
	if taskIDStr == "" {
		Error(w, http.StatusBadRequest, "task_id query parameter is required")
		return
	}
	taskID, err := strconv.ParseInt(taskIDStr, 10, 64)
	if err != nil || taskID <= 0 {
		Error(w, http.StatusBadRequest, "invalid task_id")
		return
	}

	results, err := h.queries.ListScanResults(r.Context(), db.ListScanResultsParams{
		Column1: taskID,
		TaskID:  taskID,
		Column3: "",
		Ip:      "",
		Column5: -1, // no alive filter on full export
		Alive:   0,
		Limit:   100000,
		Offset:  0,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to fetch scan results")
		return
	}

	// Set response headers
	dateStr := time.Now().Format("2006-01-02")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-results-%d-%s.csv"`, taskID, dateStr))

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	wr := csv.NewWriter(w)
	wr.UseCRLF = false
	_ = wr.Write([]string{"IP", "Alive", "RTT_ms", "SNMP_Name", "SNMP_Descr", "Brand", "Type", "Location", "Ports", "Services"})

	for _, res := range results {
		snmpName, snmpDescr, brand, devType, location := extractSNMPFields(res.SnmpData, res.Ip)
		ports := simplifyJSONList(res.Ports)
		services := simplifyJSONList(res.Services)
		alive := "no"
		if res.Alive == 1 {
			alive = "yes"
		}
		_ = wr.Write([]string{
			res.Ip,
			alive,
			fmt.Sprintf("%d", res.RttMs),
			snmpName,
			snmpDescr,
			brand,
			devType,
			location,
			ports,
			services,
		})
	}
	wr.Flush()
}

// extractSNMPFields parses snmp_data JSON to extract individual fields.
// Falls back to enrichment from snmp_data if present.
func extractSNMPFields(snmpData, _ string) (name, descr, brand, devType, location string) {
	if snmpData == "" {
		return
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(snmpData), &m); err != nil {
		return
	}
	name = m["sys_name"]
	descr = m["sys_descr"]
	location = m["sys_location"]
	brand = m["inferred_brand"]
	devType = m["inferred_type"]
	if brand == "" {
		// Derive brand from sys_descr if possible
		brand = inferBrandFromDescr(descr)
	}
	if devType == "" {
		devType = inferTypeFromDescr(descr)
	}
	return
}

// inferBrandFromDescr extracts a brand from SNMP sysDescr.
func inferBrandFromDescr(descr string) string {
	lower := strings.ToLower(descr)
	brands := []struct {
		name    string
		keyword string
	}{
		{"Cisco", "cisco"},
		{"Juniper", "juniper"},
		{"Huawei", "huawei"},
		{"HPE", "hpe"},
		{"Aruba", "aruba"},
		{"MikroTik", "mikrotik"},
		{"Ubiquiti", "ubiquiti"},
		{"Fortinet", "fortinet"},
		{"Dell", "dell"},
		{"Linux", "linux"},
		{"Windows", "windows"},
	}
	for _, b := range brands {
		if strings.Contains(lower, b.keyword) {
			return b.name
		}
	}
	return ""
}

// inferTypeFromDescr extracts a device type from SNMP sysDescr.
func inferTypeFromDescr(descr string) string {
	lower := strings.ToLower(descr)
	types := []struct {
		name    string
		keyword string
	}{
		{"router", "router"},
		{"switch", "switch"},
		{"firewall", "firewall"},
		{"ap", "access point"},
		{"server", "server"},
		{"printer", "printer"},
		{"camera", "camera"},
	}
	for _, t := range types {
		if strings.Contains(lower, t.keyword) {
			return t.name
		}
	}
	return ""
}

// simplifyJSONList converts a JSON array string to a comma-separated list.
func simplifyJSONList(raw string) string {
	if raw == "" {
		return ""
	}
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return raw
	}
	var parts []string
	for _, item := range items {
		if port, ok := item["port"]; ok {
			parts = append(parts, fmt.Sprintf("%v", port))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}

// toScanResultResponse converts a db.ScanResult to domain.ScanResultResponse.
func toScanResultResponse(r db.ScanResult) domain.ScanResultResponse {
	var runID int64
	if r.RunID != nil {
		runID = *r.RunID
	}
	return domain.ScanResultResponse{
		ID:                   r.ID,
		TaskID:               r.TaskID,
		RunID:                runID,
		IP:                   r.Ip,
		Alive:                r.Alive == 1,
		RTTMs:                r.RttMs,
		Ports:                r.Ports,
		Services:             r.Services,
		SNMPData:             r.SnmpData,
		PrometheusDetected:   r.PrometheusDetected == 1,
		PrometheusURL:        r.PrometheusUrl,
		NodeExporterDetected: r.NodeExporterDetected == 1,
		NodeExporterURL:      r.NodeExporterUrl,
		NodeExporterData:     r.NodeExporterData,
		ScannedAt:            r.ScannedAt,
	}
}

// toScanRunResponse converts a db.ScanTaskRun to domain.ScanRunResponse.
func toScanRunResponse(r db.ScanTaskRun) domain.ScanRunResponse {
	return domain.ScanRunResponse{
		ID:           r.ID,
		TaskID:       r.TaskID,
		Status:       r.Status,
		TotalHosts:   int(r.TotalHosts),
		AliveHosts:   int(r.AliveHosts),
		NewHosts:     int(r.NewHosts),
		UpdatedHosts: int(r.UpdatedHosts),
		DurationMs:   int(r.DurationMs),
		ErrorMessage: r.ErrorMessage,
		StartedAt:    r.StartedAt,
		FinishedAt:   r.FinishedAt,
		CreatedAt:    r.CreatedAt,
	}
}
