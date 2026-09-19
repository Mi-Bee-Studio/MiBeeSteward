// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/notification"
	"mibee-steward/internal/testutil"
)

// setupCoverageServer wires the route families whose handlers had no HTTP-level
// tests: notification rules, device systems, batch operations, and exports.
// It follows setupTestServer's manual-router pattern (SPA wildcard workaround).
func setupCoverageServer(t *testing.T) (*httptest.Server, *sql.DB) {
	t.Helper()

	conn, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("setup test DB: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	cfg := &config.Config{
		Server:  config.ServerConfig{Port: 0},
		Auth:    config.AuthConfig{JWTSecret: "test-secret-key-for-tests", TokenExpiry: "1h"},
		Storage: config.StorageConfig{UploadPath: t.TempDir(), MaxFileSize: 1024 * 1024},
	}
	middleware.SetJWTAuth(cfg.Auth.JWTSecret)

	queries := sqldb.New(conn)
	auditRepo := service.NewAuditRepository(conn)

	notifSvc := service.NewNotificationService(queries)
	notifDispatcher := notification.NewDispatcher(queries, nil)
	notifDispatcher.Start(context.Background())
	t.Cleanup(notifDispatcher.Stop)
	notifHandler := handler.NewNotificationHandler(notifSvc, notifDispatcher, auditRepo)

	systemSvc := service.NewDeviceSystemService(service.NewDeviceSystemRepository(conn))
	systemHandler := handler.NewDeviceSystemHandler(systemSvc)

	batchHandler := handler.NewBatchHandler(service.NewBatchService(conn, auditRepo))

	// Export needs the heartbeat store's queries for heartbeat-results export.
	hbStore, err := service.OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb.db"))
	if err != nil {
		t.Fatalf("open heartbeat store: %v", err)
	}
	t.Cleanup(func() { hbStore.Close() })
	exportHandler := handler.NewExportHandler(service.NewExportService(queries, hbStore.Queries(), conn))

	userSvc := service.NewUserService(conn, cfg.Auth.JWTSecret, time.Hour, cfg.Auth.PasswordPolicy)
	userHandler := handler.NewUserHandler(userSvc, cfg, auditRepo, nil)

	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Mount("/api/v1/auth", userHandler.Routes())

	r.Route("/api/v1/notification/rules", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/", notifHandler.CreateRule)
		r.Get("/", notifHandler.ListRules)
		r.Get("/{id}", notifHandler.GetRule)
		r.Put("/{id}", notifHandler.UpdateRule)
		r.Patch("/{id}", notifHandler.SetRuleEnabled)
		r.Delete("/{id}", notifHandler.DeleteRule)
	})

	r.Route("/api/v1/devices/{id}/systems", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", systemHandler.ListByDevice)
		r.Get("/{systemId}", systemHandler.Get)
		r.Post("/", systemHandler.Create)
		r.Put("/{systemId}", systemHandler.Update)
		r.Delete("/{systemId}", systemHandler.Delete)
	})

	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/batch-delete", batchHandler.BatchDeleteDevices)
			r.Post("/batch-update-status", batchHandler.BatchUpdateDeviceStatus)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/export", exportHandler.ExportDevices)
			r.Get("/{id}/heartbeat-results/export", exportHandler.ExportHeartbeatResults)
		})
	})

	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/batch-delete", batchHandler.BatchDeleteUsers)
	})

	r.Route("/api/v1/audit-logs", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/export", exportHandler.ExportAuditLogs)
	})

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })

	return server, conn
}

func seedCoverageDevice(t *testing.T, db *sql.DB, name, ip string) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO devices (device_uuid, name, ip_address, status) VALUES (?, ?, ?, 'unknown')`,
		"uuid-"+name, name, ip)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// seedChannel inserts a notification channel row directly (the coverage server
// does not wire the channel CRUD routes — those have their own tests).
func seedChannel(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO notification_channels (name, type, config) VALUES ('rules-hook', 'webhook', '{}')`)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// --- Notification rule endpoints ---

func TestNotificationRuleEndpoints_CRUDAndValidation(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	channelID := seedChannel(t, db)

	// Dangling channel_id → 400 with the channel-specific message.
	resp := authPost(t, server.URL+"/api/v1/notification/rules", token,
		`{"name":"orphan","event_type":"device_lost","scope_type":"all","channel_id":9999}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "channel does not exist")

	// Valid create.
	resp = authPost(t, server.URL+"/api/v1/notification/rules", token,
		`{"name":"lost-rule","event_type":"device_lost","scope_type":"all","channel_id":`+
			strconv.FormatInt(channelID, 10)+`}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, "lost-rule", created["name"])
	require.Equal(t, true, created["enabled"])
	ruleID := idToString(created["id"])

	// Invalid scope config → 400 (service validation surfaces verbatim).
	resp = authPost(t, server.URL+"/api/v1/notification/rules", token,
		`{"name":"bad","event_type":"device_lost","scope_type":"network","channel_id":`+
			strconv.FormatInt(channelID, 10)+`}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "scope_network_id")

	// List returns the wrapper shape the frontend reads.
	resp = authGet(t, server.URL+"/api/v1/notification/rules", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	rules, ok := list["rules"].([]interface{})
	require.True(t, ok, "rules list must be wrapped as {rules: [...]}")
	require.Len(t, rules, 1)
	require.Equal(t, float64(1), list["total"])

	// Get / Get missing.
	resp = authGet(t, server.URL+"/api/v1/notification/rules/"+ruleID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/notification/rules/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Update (full replace) + missing target.
	resp = authPut(t, server.URL+"/api/v1/notification/rules/"+ruleID, token,
		`{"name":"renamed","event_type":"device_changed","scope_type":"device","scope_device_uuid":"uuid-1","channel_id":`+
			strconv.FormatInt(channelID, 10)+`,"cooldown_minutes":5}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "renamed", updated["name"])
	resp = authPut(t, server.URL+"/api/v1/notification/rules/9999", token,
		`{"name":"x","event_type":"device_lost","scope_type":"all","channel_id":`+
			strconv.FormatInt(channelID, 10)+`}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Toggle enabled, then delete → 204.
	resp = authPatch(t, server.URL+"/api/v1/notification/rules/"+ruleID, token, `{"enabled":false}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var toggled map[string]interface{}
	decodeJSON(t, resp, &toggled)
	require.Equal(t, false, toggled["enabled"])

	resp = authDelete(t, server.URL+"/api/v1/notification/rules/"+ruleID, token)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// --- Device system endpoints ---

func TestDeviceSystemEndpoints_CRUD(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	deviceID := seedCoverageDevice(t, db, "sys-host", "10.9.0.1")
	devPath := "/api/v1/devices/" + strconv.FormatInt(deviceID, 10) + "/systems"

	// Invalid body shapes → 400s (name required / bad URLs / bad path ids).
	resp := authPost(t, server.URL+devPath, token, `{"name":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "name is required")
	resp = authPost(t, server.URL+devPath, token, `{"name":"web","entry_url":"not-a-url"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "entry URL")
	resp = authPost(t, server.URL+devPath, token, `{"name":"web","metrics_url":"ftp://x"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "metrics URL")

	// Create two systems (one metrics-enabled).
	resp = authPost(t, server.URL+devPath, token,
		`{"name":"web-ui","entry_url":"http://10.9.0.1:8080","category":"web_app"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, "web-ui", created["name"])
	systemID := idToString(created["id"])

	resp = authPost(t, server.URL+devPath, token,
		`{"name":"node-exporter","metrics_url":"http://10.9.0.1:9100/metrics","metrics_enabled":true,"category":"custom"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// List is wrapped + filterable by category.
	resp = authGet(t, server.URL+devPath, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	systems, ok := list["systems"].([]interface{})
	require.True(t, ok, "systems list must be wrapped as {systems: [...]}")
	require.Len(t, systems, 2)
	require.Equal(t, float64(2), list["total"])

	resp = authGet(t, server.URL+devPath+"?category=custom", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var filtered map[string]interface{}
	decodeJSON(t, resp, &filtered)
	require.Len(t, filtered["systems"], 1)

	// Get / Get missing / invalid ids.
	resp = authGet(t, server.URL+devPath+"/"+systemID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authGet(t, server.URL+devPath+"/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authGet(t, server.URL+devPath+"/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, server.URL+"/api/v1/devices/xyz/systems", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Update + missing target.
	resp = authPut(t, server.URL+devPath+"/"+systemID, token, `{"name":"web-ui-v2"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "web-ui-v2", updated["name"])
	resp = authPut(t, server.URL+devPath+"/9999", token, `{"name":"ghost"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Delete → success message; second delete → 404.
	resp = authDelete(t, server.URL+devPath+"/"+systemID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authDelete(t, server.URL+devPath+"/"+systemID, token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Batch endpoints ---

func TestBatchEndpoints_DeviceDeleteAndUpdateStatus(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	id1 := seedCoverageDevice(t, db, "batch-1", "10.9.1.1")
	id2 := seedCoverageDevice(t, db, "batch-2", "10.9.1.2")
	id3 := seedCoverageDevice(t, db, "keep", "10.9.1.3")

	// Validation: empty ids / non-positive id / bad JSON.
	resp := authPost(t, server.URL+"/api/v1/devices/batch-delete", token, `{"ids":[]}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/devices/batch-delete", token, `{"ids":[0]}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, server.URL+"/api/v1/devices/batch-delete", token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Delete two of three.
	resp = authPost(t, server.URL+"/api/v1/devices/batch-delete", token,
		`{"ids":[`+strconv.FormatInt(id1, 10)+`,`+strconv.FormatInt(id2, 10)+`]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var deleted map[string]interface{}
	decodeJSON(t, resp, &deleted)
	require.Equal(t, float64(2), deleted["deleted"])

	var remaining int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE name LIKE 'batch-%'`).Scan(&remaining))
	require.Equal(t, 0, remaining)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE name = 'keep'`).Scan(&remaining))
	require.Equal(t, 1, remaining)

	// Status update: valid value works, invalid value → 400.
	resp = authPost(t, server.URL+"/api/v1/devices/batch-update-status", token,
		`{"ids":[`+strconv.FormatInt(id3, 10)+`],"status":"offline"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, float64(1), updated["updated"])
	var status string
	require.NoError(t, db.QueryRow(`SELECT status FROM devices WHERE id = ?`, id3).Scan(&status))
	require.Equal(t, "offline", status)

	resp = authPost(t, server.URL+"/api/v1/devices/batch-update-status", token,
		`{"ids":[1],"status":"exploded"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "invalid device status")
	resp = authPost(t, server.URL+"/api/v1/devices/batch-update-status", token, `{"ids":[1]}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "status is required")
}

func TestBatchEndpoints_UserDeleteGuardsSelfDelete(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// A second, non-admin user to delete.
	res, err := db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('victim', 'v@t.com', 'x', 'viewer')`)
	require.NoError(t, err)
	victimID, err := res.LastInsertId()
	require.NoError(t, err)

	var adminID int64
	require.NoError(t, db.QueryRow(`SELECT id FROM users WHERE username = 'admin'`).Scan(&adminID))

	// Self-delete is refused with the specific 400.
	resp := authPost(t, server.URL+"/api/v1/users/batch-delete", token, `{"ids":[`+strconv.FormatInt(adminID, 10)+`]}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "cannot delete yourself")

	// Deleting the other user works.
	resp = authPost(t, server.URL+"/api/v1/users/batch-delete", token, `{"ids":[`+strconv.FormatInt(victimID, 10)+`]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var deleted map[string]interface{}
	decodeJSON(t, resp, &deleted)
	require.Equal(t, float64(1), deleted["deleted"])
}

// --- Export endpoints ---

func TestExportEndpoints_DevicesAuditLogsHeartbeat(t *testing.T) {
	server, db := setupCoverageServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)
	deviceID := seedCoverageDevice(t, db, "export-host", "10.9.2.1")

	// Devices CSV (default format) — content-type + disposition headers.
	resp := authGet(t, server.URL+"/api/v1/devices/export", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/csv; charset=utf-8", resp.Header.Get("Content-Type"))
	require.Contains(t, resp.Header.Get("Content-Disposition"), "devices.csv")
	body := readBody(t, resp)
	require.Contains(t, body, "export-host")

	// JSON variant.
	resp = authGet(t, server.URL+"/api/v1/devices/export?format=json", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	// Unsupported format → 400.
	resp = authGet(t, server.URL+"/api/v1/devices/export?format=xml", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "csv or json")

	// Audit logs export.
	resp = authGet(t, server.URL+"/api/v1/audit-logs/export", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/csv; charset=utf-8", resp.Header.Get("Content-Type"))
	require.Contains(t, resp.Header.Get("Content-Disposition"), "audit-logs.csv")

	// Heartbeat results export for a device (empty store → header-only CSV).
	resp = authGet(t, server.URL+"/api/v1/devices/"+strconv.FormatInt(deviceID, 10)+"/heartbeat-results/export", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/csv; charset=utf-8", resp.Header.Get("Content-Type"))

	// Invalid device id → 400.
	resp = authGet(t, server.URL+"/api/v1/devices/0/heartbeat-results/export", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
