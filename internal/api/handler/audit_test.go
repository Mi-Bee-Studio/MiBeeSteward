// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// These tests pin AuditHandler's List + Facets endpoints (#171): the audit-log
// read path + query-filter parsing + the facet dropdown source. Audit is
// admin-only in production (RequireAdmin); tested here directly (handler level)
// to lock the filter→response shape independent of auth wiring.

func setupAuditHandler(t *testing.T) (*AuditHandler, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return NewAuditHandler(service.NewAuditService(conn)), conn
}

func seedAudit(t *testing.T, db *sql.DB, action, resourceType string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO audit_logs (action, resource_type, resource_id, ip_address, details) VALUES (?, ?, ?, ?, '{}')`,
		action, resourceType, "1", "127.0.0.1")
	require.NoError(t, err)
}

func TestAuditHandler_List_ReturnsLogs(t *testing.T) {
	h, db := setupAuditHandler(t)
	seedAudit(t, db, "user.login", "user")
	seedAudit(t, db, "device.update", "device")

	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?limit=10", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		AuditLogs []map[string]any `json:"audit_logs"`
		Total     int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, 2, resp.Total)
	require.Len(t, resp.AuditLogs, 2)
}

func TestAuditHandler_List_FiltersByAction(t *testing.T) {
	h, db := setupAuditHandler(t)
	seedAudit(t, db, "user.login", "user")
	seedAudit(t, db, "device.update", "device")

	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?action=user.login&limit=10", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		AuditLogs []map[string]any `json:"audit_logs"`
		Total     int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, 1, resp.Total, "action filter narrows to the matching log")
	require.Len(t, resp.AuditLogs, 1)
	require.Equal(t, "user.login", resp.AuditLogs[0]["action"])
}

func TestAuditHandler_Facets(t *testing.T) {
	h, db := setupAuditHandler(t)
	seedAudit(t, db, "user.login", "user")
	seedAudit(t, db, "device.update", "device")

	rec := httptest.NewRecorder()
	h.Facets(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs/facets", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Actions       []string `json:"actions"`
		ResourceTypes []string `json:"resource_types"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.ElementsMatch(t, []string{"user.login", "device.update"}, resp.Actions)
	require.ElementsMatch(t, []string{"user", "device"}, resp.ResourceTypes)
}
