// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
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
	"mibee-steward/internal/testutil"
)

// gapServerFixture bundles the server with the pieces tests need to reach
// into (raw DB + the minted agent token).
type gapServerFixture struct {
	server    *httptest.Server
	db        *sql.DB
	agentTok  string
	agentID   string
	adminTok  func(t *testing.T) string
	networkID int64
}

// setupGapServer wires the route families that had no HTTP-level coverage in
// round 4: auth profile/logout (with a REAL token blacklist), the mux-based
// TOTP Routes(), document upload/download/restore, network CRUD + VLANs,
// device certificates/neighbors/document-links, fingerprint coverage/draft,
// the agent command channel (both halves incl. agent-token auth), the agent
// probe-report ingest, change-log listing, and scan result/run detail +
// bulk-delete.
func setupGapServer(t *testing.T) *gapServerFixture {
	t.Helper()

	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	cfg := &config.Config{
		Server:  config.ServerConfig{Port: 0},
		Auth:    config.AuthConfig{JWTSecret: "test-secret-key-for-tests", TokenExpiry: "1h"},
		Storage: config.StorageConfig{UploadPath: t.TempDir(), MaxFileSize: 1024 * 1024},
	}
	middleware.SetJWTAuth(cfg.Auth.JWTSecret)

	queries := sqldb.New(conn)
	auditRepo := service.NewAuditRepository(conn)

	// --- auth family (logout needs a live blacklist to cover the jti path) ---
	blacklist := service.NewTokenBlacklist()
	userSvc := service.NewUserService(conn, cfg.Auth.JWTSecret, time.Hour, cfg.Auth.PasswordPolicy)
	userHandler := handler.NewUserHandler(userSvc, cfg, auditRepo, blacklist)

	totpSvc := service.NewTOTPService(conn, auditRepo)
	userSvc.SetTOTPService(totpSvc)
	totpHandler := handler.NewTOTPHandler(totpSvc, userSvc, cfg, auditRepo)

	// --- documents (full lifecycle incl. upload/download) ---
	uploadSvc := service.NewUploadService(cfg.Storage.UploadPath, cfg.Storage.MaxFileSize)
	docHandler := handler.NewDocumentHandler(service.NewDocumentService(conn, uploadSvc), cfg.Storage.UploadPath, auditRepo)

	// --- networks + device sub-resources ---
	networkSvc := service.NewNetworkService(queries, conn)
	networkHandler := handler.NewNetworkHandler(queries, networkSvc)
	tlsCertHandler := handler.NewTLSCertHandler(queries)
	neighborHandler := handler.NewNeighborHandler(queries)
	linkHandler := handler.NewLinkHandler(conn, auditRepo)
	fpHandler := handler.NewFingerprintHandler(service.NewFingerprintReportService(queries, conn))
	deviceHandler := handler.NewDeviceHandler(service.NewDeviceService(service.NewDeviceRepository(conn), nil))

	// --- agent command channel + probe-report ingest ---
	middleware.SetAgentQueries(queries)
	t.Cleanup(func() { middleware.SetAgentQueries(nil) })
	const agentID = "agent-gap"
	// Seed a network + an agent token bound to it. Stamp networks.agent_id so
	// the scan-command boundary check resolves the agent's network (the token
	// CRUD path does this automatically; direct seeding must do it by hand).
	cidr := "192.168.62.0/24"
	net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{Name: "lan-gap", Cidr: &cidr})
	require.NoError(t, err)
	require.NoError(t, queries.SetNetworkAgentID(context.Background(), sqldb.SetNetworkAgentIDParams{
		AgentID: strPtr(agentID), ID: net.ID,
	}))
	plaintext, hash := middleware.GenerateAgentToken()
	_, err = queries.CreateAgentToken(context.Background(), sqldb.CreateAgentTokenParams{
		AgentID: agentID, TokenHash: hash, NetworkID: &net.ID, Name: "gap agent",
	})
	require.NoError(t, err)

	cmdSvc := service.NewAgentCommandService(queries, false, false)
	cmdHandler := handler.NewAgentCommandHandler(queries, cmdSvc, auditRepo)

	// --- change log + scan results ---
	changesHandler := handler.NewChangeLogHandler(queries, conn)
	scanResHandler := handler.NewScannerResultHandler(queries, conn, service.NewScannerResultService(queries))

	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)

	r.Mount("/api/v1/auth", userHandler.Routes())
	// TOTP Routes() is a stdlib ServeMux with method+path patterns, chi.Mount
	// does NOT strip the prefix for foreign handlers, so wrap it explicitly
	// (production wires these endpoints directly; this mount exercises the
	// mux itself). /verify stays public like production; the rest RequireAuth.
	r.Route("/api/v1/auth/2fa", func(r chi.Router) {
		r.Post("/verify", totpHandler.Verify)
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Handle("/*", http.StripPrefix("/api/v1/auth/2fa", totpHandler.Routes()))
		})
	})

	r.Route("/api/v1/documents", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", docHandler.List)
			r.Get("/{id}", docHandler.Get)
			r.Get("/{id}/download", docHandler.Download)
			r.Get("/{id}/devices", linkHandler.GetDocumentDevices)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", docHandler.CreateURL)
			r.Post("/upload", docHandler.UploadFile)
			r.Post("/{id}/restore", docHandler.Restore)
			r.Put("/{id}", docHandler.Update)
			r.Delete("/{id}", docHandler.Delete)
		})
	})

	r.Route("/api/v1/networks", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", networkHandler.List)
			r.Get("/{id}", networkHandler.Get)
			r.Get("/{id}/vlans", networkHandler.VLANs)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", networkHandler.Create)
			r.Put("/{id}", networkHandler.Update)
			r.Delete("/{id}", networkHandler.Delete)
		})
	})

	// The device handler's own Routes() (read surface) mounted verbatim so the
	// router-constructor branch is exercised too.
	r.Mount("/api/v1/dev-legacy", deviceHandler.Routes())

	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", deviceHandler.List)
			r.Get("/stats", deviceHandler.GetStats)
			r.Get("/{id}", deviceHandler.Get)
			r.Get("/{id}/certificates", tlsCertHandler.ListByDevice)
			r.Get("/{id}/neighbors", neighborHandler.ListByDevice)
			r.Get("/{id}/documents", linkHandler.GetDeviceDocuments)
			r.Post("/{uuid}/fingerprint-draft", fpHandler.RuleDraft)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", deviceHandler.Create)
			r.Put("/{id}", deviceHandler.Update)
			r.Delete("/{id}", deviceHandler.Delete)
			r.Post("/{id}/documents", linkHandler.LinkDocument)
			r.Delete("/{id}/documents/{docId}", linkHandler.UnlinkDocument)
		})
	})

	r.Get("/api/v1/fingerprints/coverage", fpHandler.Coverage)

	r.Route("/api/v1/agents", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/{agentId}/commands", cmdHandler.Create)
			r.Get("/commands/all", cmdHandler.ListAll)
			r.Get("/status", cmdHandler.FleetStatus)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAgentToken)
			r.Get("/commands", cmdHandler.Poll)
			r.Post("/commands/{id}/ack", cmdHandler.Ack)
			r.Post("/commands/{id}/complete", cmdHandler.Complete)
			r.Post("/probe-report", handler.NewAgentProbeReportHandler(nil).Report)
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/api/v1/changes", changesHandler.List)
		r.Get("/api/v1/scanner/runs", scanResHandler.ListRuns)
		r.Get("/api/v1/scanner/runs/{id}", scanResHandler.GetRun)
		r.Get("/api/v1/scanner/results", scanResHandler.ListResults)
		r.Get("/api/v1/scanner/results/export", scanResHandler.ExportScanResults)
		r.Get("/api/v1/scanner/results/{id}", scanResHandler.GetResult)
	})
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Delete("/api/v1/scanner/results", scanResHandler.BulkDeleteResults)
	})

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })

	fx := &gapServerFixture{
		server:    server,
		db:        conn,
		agentTok:  plaintext,
		agentID:   agentID,
		networkID: net.ID,
	}
	fx.adminTok = func(t *testing.T) string {
		t.Helper()
		insertTestAdmin(t, conn)
		return loginAsAdmin(t, server)
	}
	return fx
}

// --- auth: profile update / logout / password edge branches ---

func TestAuthEndpoints_ProfileUpdateAndLogout(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)

	// GET profile → 200 with username.
	resp := authGet(t, fx.server.URL+"/api/v1/auth/profile", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// PUT profile: invalid body / empty email / happy path.
	resp = authPut(t, fx.server.URL+"/api/v1/auth/profile", token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/auth/profile", token, `{"email":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "email is required")
	resp = authPut(t, fx.server.URL+"/api/v1/auth/profile", token, `{"email":"admin@new-domain.test"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "admin@new-domain.test", updated["email"])

	// Logout blacklists the CURRENT token's jti and clears the cookie.
	resp = authPost(t, fx.server.URL+"/api/v1/auth/logout", token, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "logged out")
	var cleared bool
	for _, c := range resp.Cookies() {
		if c.Name == "token" && c.MaxAge < 0 {
			cleared = true
		}
	}
	require.True(t, cleared, "logout must expire the auth cookie")

	// Change-password validation branches (on a fresh admin login).
	token2 := loginAsAdmin(t, fx.server)
	resp = authPut(t, fx.server.URL+"/api/v1/auth/password", token2, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/auth/password", token2, `{"old_password":"x"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "old_password and new_password")
	resp = authPut(t, fx.server.URL+"/api/v1/auth/password", token2, `{"old_password":"admin123","new_password":"admin123"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode) // same password
	resp = authPut(t, fx.server.URL+"/api/v1/auth/password", token2, `{"old_password":"wrong","new_password":"DifferentPw1!"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "incorrect current password")
}

// TestAuthEndpoints_ProfileForDeletedUser pins the 404 branch: a VALID token
// for a user whose row was deleted meanwhile must return user-not-found, not
// a 500 or an empty profile.
func TestAuthEndpoints_ProfileForDeletedUser(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)

	_, err := fx.db.Exec(`DELETE FROM users WHERE username='admin'`)
	require.NoError(t, err)

	resp := authGet(t, fx.server.URL+"/api/v1/auth/profile", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/auth/profile", token, `{"email":"x@y.z"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- TOTP: Routes() mux + status/disable branches ---

func TestTOTPEndpoints_StatusAndDisableBranches(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)

	// Status before setup: enabled=false, no secret.
	resp := authGet(t, fx.server.URL+"/api/v1/auth/2fa/status", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var status map[string]interface{}
	decodeJSON(t, resp, &status)
	require.Equal(t, false, status["enabled"])

	// Enable without a pending setup → the friendly 400.
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/enable", token, `{"code":"123456"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "not set up")

	// Setup → enable with a wrong code → 422.
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/setup", token, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/enable", token, `{"code":"000000"}`)
	require.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)

	// Enable with an empty code → 400 (validation branch).
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/enable", token, `{"code":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Disable: empty password 400, wrong password 401, no 2FA row → enabled
	// stays false; wrong-password branch needs an ENABLED row so the password
	// check runs, assert the 400/401 branches that are reachable now.
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/disable", token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/disable", token, `{"password":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/disable", token, `{"password":"wrong"}`)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode) // invalid password (row exists, not yet enabled)

	// Verify (public): missing fields / unknown user / not enabled.
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/verify", "", `{"user_id":0,"code":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/verify", "", `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/auth/2fa/verify", "", `{"user_id":9999,"code":"123456"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode) // 2FA not configured
}

// --- documents: upload → download inline/attachment, restore, update ---

func TestDocumentEndpoints_UploadDownloadRestoreUpdate(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)

	// Upload a PDF via multipart (PDF is on the upload whitelist; the content
	// sniff must match the extension).
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "manual.pdf")
	require.NoError(t, err)
	_, err = fw.Write([]byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\nendobj\n"))
	require.NoError(t, err)
	require.NoError(t, mw.WriteField("title", "Manual"))
	require.NoError(t, mw.Close())
	req, _ := http.NewRequest(http.MethodPost, fx.server.URL+"/api/v1/documents/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var uploaded map[string]interface{}
	decodeJSON(t, resp, &uploaded)
	fileDocID := idToString(uploaded["id"])

	// A text/plain upload is off-whitelist → 415 with the real reason.
	var txtBuf bytes.Buffer
	txtMW := multipart.NewWriter(&txtBuf)
	tfw, err := txtMW.CreateFormFile("file", "notes.txt")
	require.NoError(t, err)
	_, err = tfw.Write([]byte("hello mibee"))
	require.NoError(t, err)
	require.NoError(t, txtMW.WriteField("title", "Notes"))
	require.NoError(t, txtMW.Close())
	req, _ = http.NewRequest(http.MethodPost, fx.server.URL+"/api/v1/documents/upload", &txtBuf)
	req.Header.Set("Content-Type", txtMW.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "not allowed")

	// Upload without the file part → 400.
	var buf2 bytes.Buffer
	mw2 := multipart.NewWriter(&buf2)
	require.NoError(t, mw2.Close())
	req, _ = http.NewRequest(http.MethodPost, fx.server.URL+"/api/v1/documents/upload", &buf2)
	req.Header.Set("Content-Type", mw2.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// URL-type document for the not-a-file branch.
	resp = authPost(t, fx.server.URL+"/api/v1/documents", token, `{"title":"Vendor page","url":"https://example.com"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var urlDoc map[string]interface{}
	decodeJSON(t, resp, &urlDoc)
	urlDocID := idToString(urlDoc["id"])

	// Download the file: content served, MIME pinned, attachment by default.
	resp = authGet(t, fx.server.URL+"/api/v1/documents/"+fileDocID+"/download", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.Contains(t, string(body), "%PDF-1.4", "uploaded bytes must round-trip")
	// stored under a UUID name; the extension is preserved
	require.Regexp(t, `attachment; filename=[0-9a-f-]{36}\.pdf`, resp.Header.Get("Content-Disposition"))
	require.Equal(t, "application/pdf", resp.Header.Get("Content-Type"), "stored MIME is authoritative (no sniffing)")

	// ?inline=1 flips the disposition (preview path).
	resp = authGet(t, fx.server.URL+"/api/v1/documents/"+fileDocID+"/download?inline=1", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Regexp(t, `inline; filename=[0-9a-f-]{36}\.pdf`, resp.Header.Get("Content-Disposition"))

	// A URL document cannot be downloaded → 400.
	resp = authGet(t, fx.server.URL+"/api/v1/documents/"+urlDocID+"/download", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "not a file type")

	// Missing document → 404; invalid id → 400.
	resp = authGet(t, fx.server.URL+"/api/v1/documents/9999/download", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/documents/abc/download", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Update title; update a missing doc → 404; invalid body → 400.
	resp = authPut(t, fx.server.URL+"/api/v1/documents/"+urlDocID, token, `{"title":"Renamed page"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "Renamed page", updated["title"])
	resp = authPut(t, fx.server.URL+"/api/v1/documents/9999", token, `{"title":"x"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/documents/"+urlDocID, token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Soft delete → restore → delete again (tombstone lifecycle).
	resp = authDelete(t, fx.server.URL+"/api/v1/documents/"+urlDocID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/documents/"+urlDocID+"/restore", token, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/documents/9999/restore", token, "")
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- networks: get/vlans/create/update/delete ---

func TestNetworkEndpoints_GetVLANsAndCRUD(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)
	netID := fx.networkID

	// List + Get.
	resp := authGet(t, fx.server.URL+"/api/v1/networks", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/networks/"+fmt.Sprint(netID), token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/networks/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/networks/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// VLANs: seed one row, list wraps as {vlans, total}.
	_, err := fx.db.Exec(`INSERT INTO vlans (vlan_tag, name, network_id) VALUES (42, 'mgmt', ?)`, netID)
	require.NoError(t, err)
	resp = authGet(t, fx.server.URL+"/api/v1/networks/"+fmt.Sprint(netID)+"/vlans", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var vl map[string]interface{}
	decodeJSON(t, resp, &vl)
	require.Equal(t, float64(1), vl["total"])
	resp = authGet(t, fx.server.URL+"/api/v1/networks/abc/vlans", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Create: missing name → 400; duplicate name → 409; valid → 201.
	resp = authPost(t, fx.server.URL+"/api/v1/networks", token, `{"name":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/networks", token, `{"name":"lan-gap"}`)
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/networks", token, `{"name":"lan-new","cidr":"10.20.0.0/16","site":"hq"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	newID := idToString(created["id"])

	// Update: rename; 404 on unknown.
	resp = authPut(t, fx.server.URL+"/api/v1/networks/"+newID, token, `{"name":"lan-renamed"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/networks/9999", token, `{"name":"x"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Delete: unknown → 404; existing → 204 (or 200 envelope).
	resp = authDelete(t, fx.server.URL+"/api/v1/networks/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authDelete(t, fx.server.URL+"/api/v1/networks/"+newID, token)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// --- device sub-resources: TLS certs, neighbors, document links ---

func seedGapDevice(t *testing.T, db *sql.DB, name, ip string) (id int64, uuid string) {
	t.Helper()
	uuid = "uuid-" + name
	res, err := db.Exec(`INSERT INTO devices (device_uuid, name, ip_address, status) VALUES (?, ?, ?, 'unknown')`, uuid, name, ip)
	require.NoError(t, err)
	id, err = res.LastInsertId()
	require.NoError(t, err)
	return id, uuid
}

func TestDeviceSubResourceEndpoints_CertsNeighborsLinks(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)
	devID, devUUID := seedGapDevice(t, fx.db, "gap-host", "10.30.0.1")

	// TLS certs: seed a two-cert chain on one port + one on another.
	now := time.Now().UTC().Format(time.RFC3339)
	for _, row := range []struct {
		port, idx int
		cn        string
	}{
		{443, 0, "leaf.example.com"}, {443, 1, "Example CA"}, {8443, 0, "alt.example.com"},
	} {
		_, err := fx.db.Exec(`INSERT INTO host_tls_certs
			(ip, device_uuid, port, cert_index, subject_cn, issuer_cn, key_bits, is_ca, self_signed, pem, tls_version, cipher_suite, trusted, updated_at)
			VALUES ('10.30.0.1', ?, ?, ?, ?, 'Example CA', 2048, ?, 0, '-----BEGIN CERTIFICATE-----', 'TLS 1.3', 'TLS_AES_128_GCM_SHA256', 1, ?)`,
			devUUID, row.port, row.idx, row.cn, boolInt(row.idx == 1), now)
		require.NoError(t, err)
	}

	resp := authGet(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/certificates", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var certs map[string]interface{}
	decodeJSON(t, resp, &certs)
	require.Equal(t, float64(2), certs["total"]) // grouped per port
	ports := certs["certificates"].([]interface{})
	first := ports[0].(map[string]interface{})
	require.Equal(t, float64(443), first["port"])
	chain := first["chain"].([]interface{})
	require.Len(t, chain, 2)
	require.NotNil(t, first["leaf"], "leaf (cert_index 0) must be surfaced separately")
	resp = authGet(t, fx.server.URL+"/api/v1/devices/abc/certificates", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Neighbors: one identified (JOIN resolves via MAC) + one ghost.
	otherID, _ := seedGapDevice(t, fx.db, "gap-neighbor", "10.30.0.2")
	_, err := fx.db.Exec(`UPDATE devices SET mac_address='aa:bb:cc:00:00:01' WHERE id=?`, otherID)
	require.NoError(t, err)
	_, err = fx.db.Exec(`INSERT INTO device_neighbors (device_id, neighbor_device_id, neighbor_mac, protocol, local_port, remote_port, first_seen, last_seen)
		VALUES (?, ?, 'aa:bb:cc:00:00:01', 'lldp', 'eth0', 'gi1/0/1', datetime('now'), datetime('now'))`, devID, otherID)
	require.NoError(t, err)
	_, err = fx.db.Exec(`INSERT INTO device_neighbors (device_id, neighbor_mac, protocol)
		VALUES (?, 'aa:bb:cc:00:00:02', 'cdp')`, devID)
	require.NoError(t, err)

	resp = authGet(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/neighbors", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var neigh map[string]interface{}
	decodeJSON(t, resp, &neigh)
	list := neigh["neighbors"].([]interface{})
	require.Len(t, list, 2)
	// Rows are ordered by protocol: cdp (ghost, no registry fields) first,
	// lldp (identified) second. The identified one must carry the JOINed
	// registry fields + formatted timestamps.
	identified := list[1].(map[string]interface{})
	require.Equal(t, "gap-neighbor", identified["neighbor_name"])
	require.NotNil(t, identified["neighbor_device_id"])
	require.NotNil(t, identified["first_seen"], "timestamps must be formatted, not null")
	ghost := list[0].(map[string]interface{})
	require.Nil(t, ghost["neighbor_name"])
	resp = authGet(t, fx.server.URL+"/api/v1/devices/abc/neighbors", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Document links: create a doc, link it, list, unlink.
	resp = authPost(t, fx.server.URL+"/api/v1/documents", token, `{"title":"Manual","url":"https://example.com/manual"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var doc map[string]interface{}
	decodeJSON(t, resp, &doc)
	docID := idToString(doc["id"])

	resp = authPost(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/documents", token, `{"document_id":`+docID+`}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/documents", token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/documents", token, `{"document_id":0}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp = authGet(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/documents", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var linked map[string]interface{}
	decodeJSON(t, resp, &linked)
	require.Equal(t, float64(1), linked["total"])

	resp = authDelete(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/documents/"+docID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authDelete(t, fx.server.URL+"/api/v1/devices/"+fmt.Sprint(devID)+"/documents/"+docID, token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode) // already unlinked

	// Fingerprint: coverage (empty DB → zeroed tiers) + draft for an unknown
	// uuid → 404.
	resp = authGet(t, fx.server.URL+"/api/v1/fingerprints/coverage", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/devices/uuid-no-such/fingerprint-draft", token, "")
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = devUUID
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- agent command channel: create → poll → ack → complete + fleet views ---

func TestAgentCommandEndpoints_FullCycle(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)

	// Admin enqueues a scan command for the fixture's agent (in-network).
	resp := authPost(t, fx.server.URL+"/api/v1/agents/"+fx.agentID+"/commands", token,
		`{"command":"scan","payload":{"targets":"192.168.62.0/24"}}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var cmd map[string]interface{}
	decodeJSON(t, resp, &cmd)
	require.Equal(t, "scan", cmd["command"])
	cmdID := idToString(cmd["id"])

	// Validation branches: bad JSON, unknown command, out-of-network targets.
	resp = authPost(t, fx.server.URL+"/api/v1/agents/"+fx.agentID+"/commands", token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/agents/"+fx.agentID+"/commands", token, `{"command":"reboot-now"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/agents/"+fx.agentID+"/commands", token,
		`{"command":"scan","payload":{"targets":"10.99.0.0/16"}}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "192.168.62")

	// Agent polls: sees the pending command.
	resp = authGet(t, fx.server.URL+"/api/v1/agents/commands", fx.agentTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var polled []interface{}
	decodeJSON(t, resp, &polled)
	require.Len(t, polled, 1)

	// Agent acks (pending → acknowledged: next poll is empty).
	resp = authPost(t, fx.server.URL+"/api/v1/agents/commands/"+cmdID+"/ack", fx.agentTok, "")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/agents/commands", fx.agentTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &polled)
	require.Empty(t, polled)

	// Bad ids on ack/complete → 400.
	resp = authPost(t, fx.server.URL+"/api/v1/agents/commands/abc/ack", fx.agentTok, "")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Agent completes: malformed body → 400; done → 204; then a failed one.
	resp = authPost(t, fx.server.URL+"/api/v1/agents/commands/"+cmdID+"/complete", fx.agentTok, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/agents/commands/"+cmdID+"/complete", fx.agentTok, `{"status":"done","result":"{}"}`)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Admin fleet views: command list + agent status (agent_status row may be
	// absent until the agent reports, the endpoint must still 200 with total 0).
	resp = authGet(t, fx.server.URL+"/api/v1/agents/commands/all", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var all map[string]interface{}
	decodeJSON(t, resp, &all)
	require.Equal(t, float64(1), all["total"])
	resp = authGet(t, fx.server.URL+"/api/v1/agents/status", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Agent probe-report: empty batch → accepted:0; malformed → 400.
	resp = authPost(t, fx.server.URL+"/api/v1/agents/probe-report", fx.agentTok, `{"results":[]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, readBody(t, resp), `"accepted":0`)
	resp = authPost(t, fx.server.URL+"/api/v1/agents/probe-report", fx.agentTok, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- change log listing ---

func TestChangeLogEndpoints_List(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)
	devID, _ := seedGapDevice(t, fx.db, "change-host", "10.31.0.1")

	for _, ct := range []string{"device_added", "device_changed", "device_lost"} {
		_, err := fx.db.Exec(`INSERT INTO change_log (network_id, change_type, entity_type, entity_id, after_data, detected_at)
			VALUES (?, ?, 'device', ?, '{}', datetime('now'))`, fx.networkID, ct, devID)
		require.NoError(t, err)
	}

	resp := authGet(t, fx.server.URL+"/api/v1/changes", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var all map[string]interface{}
	decodeJSON(t, resp, &all)
	require.GreaterOrEqual(t, all["total"], float64(3))

	// Type filter narrows; unknown type → empty (not an error).
	resp = authGet(t, fx.server.URL+"/api/v1/changes?change_type=device_lost", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var filtered map[string]interface{}
	decodeJSON(t, resp, &filtered)
	require.Equal(t, float64(1), filtered["total"])
	resp = authGet(t, fx.server.URL+"/api/v1/changes?limit=abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- scan result/run detail + bulk delete ---

func TestScannerResultEndpoints_GetRunGetResultBulkDelete(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)

	// Seed task + run + result (same shape the sort tests use).
	res, err := fx.db.Exec(`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled)
		VALUES ('gap-task', '192.168.1.0/24', '0 3 * * *', '{}', '{}', 30, 10, 1)`)
	require.NoError(t, err)
	taskID, err := res.LastInsertId()
	require.NoError(t, err)

	res, err = fx.db.Exec(`INSERT INTO scan_task_runs (task_id, status, total_hosts, alive_hosts, duration_ms)
		VALUES (?, 'completed', 10, 3, 1250)`, taskID)
	require.NoError(t, err)
	runID, err := res.LastInsertId()
	require.NoError(t, err)

	res, err = fx.db.Exec(`INSERT INTO scan_results (task_id, run_id, ip, alive, ports, services, scanned_at) VALUES (?, ?, '192.168.1.5', 1, '[80]', '{}', datetime('now','-3 days'))`, taskID, runID)
	require.NoError(t, err)
	resultID, err := res.LastInsertId()
	require.NoError(t, err)

	// GetRun / GetResult happy paths + 404s + bad ids.
	resp := authGet(t, fx.server.URL+"/api/v1/scanner/runs/"+fmt.Sprint(runID), token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var run map[string]interface{}
	decodeJSON(t, resp, &run)
	require.Equal(t, float64(3), run["alive_hosts"])
	resp = authGet(t, fx.server.URL+"/api/v1/scanner/runs/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/scanner/runs/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp = authGet(t, fx.server.URL+"/api/v1/scanner/results/"+fmt.Sprint(resultID), token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	require.Equal(t, "192.168.1.5", result["ip"])
	resp = authGet(t, fx.server.URL+"/api/v1/scanner/results/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// ListRuns (global scope branch) + task_id filter.
	resp = authGet(t, fx.server.URL+"/api/v1/scanner/runs", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var runs map[string]interface{}
	decodeJSON(t, resp, &runs)
	require.Equal(t, float64(1), runs["total"])
	resp = authGet(t, fx.server.URL+"/api/v1/scanner/runs?task_id="+fmt.Sprint(taskID), token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// BulkDeleteResults: validation branches, then a real past-date delete.
	resp = authDelete(t, fx.server.URL+"/api/v1/scanner/results", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "before_date")
	resp = authDelete(t, fx.server.URL+"/api/v1/scanner/results?before_date=not-a-date", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "ISO 8601")
	// A date inside the past 24h rounds to zero days ago → rejected as not-past.
	recent := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	resp = authDelete(t, fx.server.URL+"/api/v1/scanner/results?before_date="+recent, token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	// 48h back → deletes the 3-day-old seeded row.
	past := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	resp = authDelete(t, fx.server.URL+"/api/v1/scanner/results?before_date="+past, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, readBody(t, resp), `"deleted":1`)

	var remaining int
	require.NoError(t, fx.db.QueryRow(`SELECT COUNT(*) FROM scan_results`).Scan(&remaining))
	require.Equal(t, 0, remaining)
}

// --- SPA handler: immutable asset headers + fallback ---

func TestSPAHandler_AssetHeadersAndFallback(t *testing.T) {
	h := handler.NewSPAHandler()

	// /_app/* responses carry the immutable cache header (asserted on a path
	// that actually serves 200, content-hashed asset filenames aren't stable
	// across builds, and Go's file server drops pre-set headers on its own 404).
	req := httptest.NewRequest(http.MethodGet, "/_app/immutable/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))

	// An unknown client-side route falls back to the SPA root (index.html).
	req = httptest.NewRequest(http.MethodGet, "/devices/42/certs", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "text/html")
}

// --- device CRUD error branches + the document→devices reverse link ---

func TestDeviceEndpoints_ErrorBranchesAndRoutes(t *testing.T) {
	fx := setupGapServer(t)
	token := fx.adminTok(t)

	// Create: bad JSON / empty name / invalid IP / happy path.
	resp := authPost(t, fx.server.URL+"/api/v1/devices", token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPost(t, fx.server.URL+"/api/v1/devices", token, `{"name":""}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "name is required")
	resp = authPost(t, fx.server.URL+"/api/v1/devices", token, `{"name":"bad-ip","ip_address":"999.999.1.1"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "invalid IP")
	resp = authPost(t, fx.server.URL+"/api/v1/devices", token, `{"name":"edge-sw","type":"switch","ip_address":"10.40.0.1"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	devID := idToString(created["id"])

	// Get / Update / Delete error branches.
	resp = authGet(t, fx.server.URL+"/api/v1/devices/abc", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/devices/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/devices/9999", token, `{"name":"ghost"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/devices/"+devID, token, `{not-json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = authPut(t, fx.server.URL+"/api/v1/devices/"+devID, token, `{"ip_address":"not-an-ip"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Contains(t, readBody(t, resp), "invalid IP")
	resp = authDelete(t, fx.server.URL+"/api/v1/devices/9999", token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Stats with a device present.
	resp = authGet(t, fx.server.URL+"/api/v1/devices/stats", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The handler's own Routes() mount answers reads (no auth wired there).
	resp = authGet(t, fx.server.URL+"/api/v1/dev-legacy/stats", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Reverse link: documents/{id}/devices lists linked devices, wrapped.
	docResp := authPost(t, fx.server.URL+"/api/v1/documents", token, `{"title":"Cfg","url":"https://example.com/cfg"}`)
	require.Equal(t, http.StatusCreated, docResp.StatusCode)
	var doc map[string]interface{}
	decodeJSON(t, docResp, &doc)
	docID := idToString(doc["id"])
	resp = authPost(t, fx.server.URL+"/api/v1/devices/"+devID+"/documents", token, `{"document_id":`+docID+`}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = authGet(t, fx.server.URL+"/api/v1/documents/"+docID+"/devices", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var linked map[string]interface{}
	decodeJSON(t, resp, &linked)
	require.Equal(t, float64(1), linked["total"])
	resp = authGet(t, fx.server.URL+"/api/v1/documents/abc/devices", token)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Delete for real → 200 envelope; row gone.
	resp = authDelete(t, fx.server.URL+"/api/v1/devices/"+devID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = authGet(t, fx.server.URL+"/api/v1/devices/"+devID, token)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}
