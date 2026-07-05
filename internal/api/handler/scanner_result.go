package handler

import (
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
}

// NewScannerResultHandler creates a new ScannerResultHandler.
func NewScannerResultHandler(queries *db.Queries) *ScannerResultHandler {
	return &ScannerResultHandler{queries: queries}
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

	results, err := h.queries.ListScanResults(r.Context(), db.ListScanResultsParams{
		Column1: taskID,
		TaskID:  taskID,
		Column3: ipFilter,
		Ip:      ipFilter,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		slog.Error("ListScanResults failed", "task_id", taskID, "ip", ipFilter, "limit", limit, "offset", offset, "error", err)
		Error(w, http.StatusInternalServerError, "failed to list scan results")
		return
	}

	if results == nil {
		results = []db.ScanResult{}
	}

	total, err := h.queries.CountScanResults(r.Context(), db.CountScanResultsParams{
		Column1: taskID,
		TaskID:  taskID,
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
