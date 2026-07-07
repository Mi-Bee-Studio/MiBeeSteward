package handler_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/config"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/notification"
	"mibee-steward/internal/testutil"

	_ "modernc.org/sqlite"
)

// setupTestServer creates an in-memory SQLite database, runs migrations, and
// returns an httptest.Server wired to a test router with all API endpoints.
// Note: We build the router manually (instead of using routes.NewRouter) to
// avoid the SPA handler's wildcard pattern which panics in chi v5.2.5.
func setupTestServer(t *testing.T) (*httptest.Server, *sql.DB) {
	t.Helper()

	db, err := testutil.SetupTestDBFromSchema()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	cfg := &config.Config{
		Server:  config.ServerConfig{Port: 0},
		Auth:    config.AuthConfig{JWTSecret: "test-secret-key-for-tests", TokenExpiry: "1h"},
		Storage: config.StorageConfig{UploadPath: t.TempDir(), MaxFileSize: 1024 * 1024},
	}

	// Initialize JWT auth
	middleware.SetJWTAuth(cfg.Auth.JWTSecret)

	expiry := 1 * time.Hour
	if cfg.Auth.TokenExpiry != "" {
		if d, parseErr := time.ParseDuration(cfg.Auth.TokenExpiry); parseErr == nil {
			expiry = d
		}
	}

	// User service and handler
	userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry)
	auditRepo := repository.NewAuditRepository(db)
	userHandler := handler.NewUserHandler(userSvc, cfg, auditRepo, nil)

	// Device handler
	deviceRepo := repository.NewDeviceRepository(db)
	deviceSvc := service.NewDeviceService(deviceRepo, nil)
	deviceHandler := handler.NewDeviceHandler(deviceSvc)

	// Document handler
	uploadPath := cfg.Storage.UploadPath
	if uploadPath == "" {
		uploadPath = "./data/uploads"
	}
	maxFileSize := cfg.Storage.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = 10485760
	}
	uploadSvc := service.NewUploadService(uploadPath, maxFileSize)
	docSvc := service.NewDocumentService(db, uploadSvc)
	docHandler := handler.NewDocumentHandler(docSvc, uploadPath, auditRepo)

	// Notification handler
	queries := sqldb.New(db)
	notifSvc := service.NewNotificationService(queries)
	notifDispatcher := notification.NewDispatcher(queries, nil)
	notifDispatcher.Start(context.Background())
	notificationHandler := handler.NewNotificationHandler(notifSvc, notifDispatcher, auditRepo)

	// Build router
	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP) //nolint:staticcheck // SA1019 deprecated; mirrors production chain
	r.Use(chimw.Recoverer)

	// Public health endpoint
	r.Get("/api/v1/health", handler.HealthHandler(db))

	// Auth routes
	r.Mount("/api/v1/auth", userHandler.Routes())

	// Admin-only user list
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/", userHandler.ListUsers)
	})

	// Device routes
	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", deviceHandler.List)
			r.Get("/stats", deviceHandler.GetStats)
			r.Get("/{id}", deviceHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", deviceHandler.Create)
			r.Put("/{id}", deviceHandler.Update)
			r.Delete("/{id}", deviceHandler.Delete)
		})
	})

	// Document routes
	r.Route("/api/v1/documents", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", docHandler.List)
			r.Get("/{id}", docHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", docHandler.CreateURL)
			r.Delete("/{id}", docHandler.Delete)
		})
	})

	// Notification routes
	r.Route("/api/v1/notification/channels", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/", notificationHandler.CreateChannel)
		r.Get("/", notificationHandler.ListChannels)
		r.Get("/{id}", notificationHandler.GetChannel)
		r.Put("/{id}", notificationHandler.UpdateChannel)
		r.Delete("/{id}", notificationHandler.DeleteChannel)
		r.Post("/{id}/test", notificationHandler.TestChannel)
	})
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/api/v1/notification/logs", notificationHandler.ListNotificationLogs)
	})

	// Prometheus metrics
	r.Handle("/metrics", handler.MetricsHandler())

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })

	return server, db
}

// insertTestAdmin inserts a pre-hashed admin user directly into the database
// to bypass the chicken-and-egg problem (register requires admin JWT).
func insertTestAdmin(t *testing.T, db *sql.DB) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	require.NoError(t, err)
	_, err = db.Exec(
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
		"admin", "admin@test.com", string(hash), "admin",
	)
	require.NoError(t, err)
}

// loginAsAdmin logs in with the seeded admin and returns the JWT token.
func loginAsAdmin(t *testing.T, server *httptest.Server) string {
	t.Helper()
	body := `{"username":"admin","password":"admin123"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	token, ok := result["token"].(string)
	require.True(t, ok, "login response should contain token")
	return token
}

// idToString converts a JSON-decoded numeric ID to a string for URL paths.
func idToString(id interface{}) string {
	return fmt.Sprintf("%v", id)
}

// authGet performs an authenticated GET request.
func authGet(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// authPost performs an authenticated POST request with JSON body.
func authPost(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// authPut performs an authenticated PUT request with JSON body.
func authPut(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("PUT", url, bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// authDelete performs an authenticated DELETE request.
func authDelete(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("DELETE", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// decodeJSON reads the response body and decodes it into target.
func decodeJSON(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()
	defer resp.Body.Close()
	err := json.NewDecoder(resp.Body).Decode(target)
	require.NoError(t, err)
}

// readBody reads and returns the response body as a string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

// --- Health Tests ---

func TestHealthEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	require.Equal(t, "ok", result["status"])
}

// --- Auth Flow Tests ---

func TestAuthLogin_Success(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	body := `{"username":"admin","password":"admin123"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, resp, &result)

	token, ok := result["token"].(string)
	require.True(t, ok, "response should contain a token")
	require.NotEmpty(t, token)

	user, ok := result["user"].(map[string]interface{})
	require.True(t, ok, "response should contain user object")
	require.Equal(t, "admin", user["username"])
	require.Equal(t, "admin", user["role"])
}

func TestAuthLogin_InvalidCredentials(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	body := `{"username":"admin","password":"wrong"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthLogin_MissingFields(t *testing.T) {
	server, _ := setupTestServer(t)

	body := `{"username":"admin"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAuthProfile_WithToken(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authGet(t, server.URL+"/api/v1/auth/profile", token)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	require.Equal(t, "admin", result["username"])
	require.Equal(t, "admin@test.com", result["email"])
	require.Equal(t, "admin", result["role"])
}

func TestAuthProfile_WithoutToken(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/auth/profile")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthProfile_InvalidToken(t *testing.T) {
	server, _ := setupTestServer(t)

	resp := authGet(t, server.URL+"/api/v1/auth/profile", "invalid-token")
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- Device CRUD Tests ---

func TestDeviceCRUD(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Create device
	createBody := `{"name":"Test Server","type":"pc","brand":"Dell","ip_address":"192.168.1.100","location":"Server Room"}`
	resp := authPost(t, server.URL+"/api/v1/devices", token, createBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, "Test Server", created["name"])
	require.Equal(t, "pc", created["type"])
	require.Equal(t, "Dell", created["brand"])

	deviceID := idToString(created["id"])

	// List devices
	resp = authGet(t, server.URL+"/api/v1/devices", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	devices, ok := list["devices"].([]interface{})
	require.True(t, ok)
	require.Len(t, devices, 1)

	// Get device by ID
	resp = authGet(t, server.URL+"/api/v1/devices/"+deviceID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var fetched map[string]interface{}
	decodeJSON(t, resp, &fetched)
	require.Equal(t, "Test Server", fetched["name"])

	// Update device
	updateBody := `{"name":"Updated Server","location":"Data Center"}`
	resp = authPut(t, server.URL+"/api/v1/devices/"+deviceID, token, updateBody)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "Updated Server", updated["name"])
	require.Equal(t, "Data Center", updated["location"])

	// Get stats
	resp = authGet(t, server.URL+"/api/v1/devices/stats", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var stats map[string]interface{}
	decodeJSON(t, resp, &stats)
	require.NotNil(t, stats["by_status"])

	// Delete device
	resp = authDelete(t, server.URL+"/api/v1/devices/"+deviceID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify deletion — list should be empty
	resp = authGet(t, server.URL+"/api/v1/devices", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var afterDelete map[string]interface{}
	decodeJSON(t, resp, &afterDelete)
	afterDevices, ok := afterDelete["devices"].([]interface{})
	require.True(t, ok)
	require.Len(t, afterDevices, 0)
}

func TestDeviceCreate_RequiresAdmin(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	// Create a regular user directly
	hash, err := bcrypt.GenerateFromPassword([]byte("user123"), bcrypt.DefaultCost)
	require.NoError(t, err)
	_, err = db.Exec(
		"INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
		"user", "user@test.com", string(hash), "user",
	)
	require.NoError(t, err)

	// Login as regular user
	body := `{"username":"user","password":"user123"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	var loginResp map[string]interface{}
	decodeJSON(t, resp, &loginResp)
	userToken := loginResp["token"].(string)

	// Try creating a device as regular user (should be forbidden)
	createBody := `{"name":"Unauthorized Device"}`
	resp = authPost(t, server.URL+"/api/v1/devices", userToken, createBody)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// --- Document Tests ---

func TestDocumentURL_CRUD(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Create URL document
	createBody := `{"title":"Test Doc","type":"url","url":"https://example.com","description":"A test document"}`
	resp := authPost(t, server.URL+"/api/v1/documents", token, createBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, "Test Doc", created["title"])
	require.Equal(t, "url", created["type"])

	docID := idToString(created["id"])

	// List documents
	resp = authGet(t, server.URL+"/api/v1/documents", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var list map[string]interface{}
	decodeJSON(t, resp, &list)
	docs, ok := list["documents"].([]interface{})
	require.True(t, ok)
	require.Len(t, docs, 1)

	// Delete document
	resp = authDelete(t, server.URL+"/api/v1/documents/"+docID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify deletion
	resp = authGet(t, server.URL+"/api/v1/documents", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var afterDelete map[string]interface{}
	decodeJSON(t, resp, &afterDelete)
	afterDocs, ok := afterDelete["documents"].([]interface{})
	require.True(t, ok)
	require.Len(t, afterDocs, 0)
}

// --- Metrics Tests ---

func TestMetricsEndpoint(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	// Create a device so that device metrics get recorded
	createBody := `{"name":"Metrics Test Device","type":"pc","ip_address":"10.0.0.1"}`
	resp := authPost(t, server.URL+"/api/v1/devices", token, createBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Seed Prometheus metrics from the database
	handler.UpdateDeviceMetrics(context.Background(), db)

	resp, err := http.Get(server.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := readBody(t, resp)
	require.Contains(t, body, "mibee_")
}

// --- Auth Required Tests ---

func TestDeviceEndpoints_RequireAuth(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/devices")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDocumentEndpoints_RequireAuth(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/documents")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
