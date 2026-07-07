package handler_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/config"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service"
)

// setupExtendedTestServer creates a test server with additional routes
// (document PUT, heartbeat configs) beyond what setupTestServer provides.
func setupExtendedTestServer(t *testing.T) (*httptest.Server, *sql.DB) {
	t.Helper()

	origServer, db := setupTestServer(t)

	cfg := &config.Config{
		Server:  config.ServerConfig{Port: 0},
		Auth:    config.AuthConfig{JWTSecret: "test-secret-key-for-tests", TokenExpiry: "1h"},
		Storage: config.StorageConfig{UploadPath: t.TempDir(), MaxFileSize: 1024 * 1024},
	}
	middleware.SetJWTAuth(cfg.Auth.JWTSecret)

	uploadPath := cfg.Storage.UploadPath
	maxFileSize := cfg.Storage.MaxFileSize
	uploadSvc := service.NewUploadService(uploadPath, maxFileSize)
	docSvc := service.NewDocumentService(db, uploadSvc)
	auditRepo := repository.NewAuditRepository(db)
	docHandler := handler.NewDocumentHandler(docSvc, uploadPath, auditRepo)

	// HeartbeatService needs its dedicated store; use a temp file.
	hbStore, err := service.OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb.db"))
	if err != nil {
		t.Fatalf("open heartbeat store: %v", err)
	}
	t.Cleanup(func() { hbStore.Close() })
	hbStore.Start(context.Background())
	heartbeatSvc := service.NewHeartbeatService(db, hbStore, cfg)
	heartbeatHandler := handler.NewHeartbeatHandler(heartbeatSvc)

	deviceRepo := repository.NewDeviceRepository(db)
	deviceSvc := service.NewDeviceService(deviceRepo, nil)
	deviceHandler := handler.NewDeviceHandler(deviceSvc)

	expiry := 1 * time.Hour
	if cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.TokenExpiry); err == nil {
			expiry = d
		}
	}
	userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry)
	userHandler := handler.NewUserHandler(userSvc, cfg, auditRepo, nil)

	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP) //nolint:staticcheck // SA1019 deprecated; mirrors production chain
	r.Use(chimw.Recoverer)

	r.Get("/api/v1/health", handler.HealthHandler(db))
	r.Mount("/api/v1/auth", userHandler.Routes())

	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/", userHandler.ListUsers)
	})

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

	r.Route("/api/v1/documents", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", docHandler.List)
			r.Get("/{id}", docHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", docHandler.CreateURL)
			r.Put("/{id}", docHandler.Update)
			r.Delete("/{id}", docHandler.Delete)
		})
	})

	r.Route("/api/v1/devices/{id}/heartbeat-configs", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", heartbeatHandler.ListConfigs)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", heartbeatHandler.CreateConfig)
		})
	})

	r.Handle("/metrics", handler.MetricsHandler())

	origServer.Close()
	extServer := httptest.NewServer(r)
	t.Cleanup(func() { extServer.Close() })

	return extServer, db
}

func TestExtended_DeviceStats_ByStatusAndType(t *testing.T) {
	server, db := setupExtendedTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	devices := []string{
		`{"name":"PC-1","type":"pc","ip_address":"10.0.0.1"}`,
		`{"name":"PC-2","type":"pc","ip_address":"10.0.0.2"}`,
		`{"name":"IoT-Sensor","type":"iot","ip_address":"10.0.1.1"}`,
		`{"name":"Embedded-1","type":"embedded","ip_address":"10.0.2.1"}`,
	}
	for _, body := range devices {
		resp := authPost(t, server.URL+"/api/v1/devices", token, body)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		readBody(t, resp)
	}

	resp := authGet(t, server.URL+"/api/v1/devices/stats", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var stats map[string]interface{}
	decodeJSON(t, resp, &stats)

	byStatus, ok := stats["by_status"].(map[string]interface{})
	require.True(t, ok, "response should contain by_status map")
	require.NotEmpty(t, byStatus)

	byType, ok := stats["by_type"].(map[string]interface{})
	require.True(t, ok, "response should contain by_type map")
	require.NotEmpty(t, byType)

	require.Equal(t, 4, toInt(byStatus["unknown"]), "should have 4 devices with unknown status")
	require.Equal(t, 2, toInt(byType["pc"]), "should have 2 pc devices")
	require.Equal(t, 1, toInt(byType["iot"]), "should have 1 iot device")
	require.Equal(t, 1, toInt(byType["embedded"]), "should have 1 embedded device")
}

func TestExtended_HeartbeatConfig_WrappedResponse(t *testing.T) {
	server, db := setupExtendedTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/devices", token,
		`{"name":"HB-Device","type":"pc","ip_address":"10.1.1.1"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var dev map[string]interface{}
	decodeJSON(t, resp, &dev)
	deviceID := idToString(dev["id"])

	hbConfigs := []string{
		`{"method":"icmp","target":"10.1.1.1","interval_seconds":30,"timeout_seconds":5}`,
		`{"method":"tcp","target":"10.1.1.1:80","interval_seconds":60,"timeout_seconds":3}`,
	}
	for _, cfg := range hbConfigs {
		resp := authPost(t, server.URL+"/api/v1/devices/"+deviceID+"/heartbeat-configs", token, cfg)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		readBody(t, resp)
	}

	resp = authGet(t, server.URL+"/api/v1/devices/"+deviceID+"/heartbeat-configs", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, resp, &result)

	configsList, ok := result["configs"].([]interface{})
	require.True(t, ok, "response should contain configs array (wrapped, not bare)")
	total, ok := result["total"].(float64)
	require.True(t, ok, "response should contain total field")

	require.Len(t, configsList, 2, "configs array should have 2 items")
	require.Equal(t, float64(2), total, "total should match array length")
}

func TestExtended_DocumentUpdate(t *testing.T) {
	server, db := setupExtendedTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	resp := authPost(t, server.URL+"/api/v1/documents", token,
		`{"title":"Original Doc","type":"url","url":"https://example.com","description":"original description"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	require.Equal(t, "Original Doc", created["title"])
	docID := idToString(created["id"])

	resp = authPut(t, server.URL+"/api/v1/documents/"+docID, token,
		`{"title":"Updated Doc","url":"https://updated.example.com","description":"updated description"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	require.Equal(t, "Updated Doc", updated["title"])
	require.Equal(t, "https://updated.example.com", updated["url"])
	require.Equal(t, "updated description", updated["description"])

	resp = authGet(t, server.URL+"/api/v1/documents/"+docID, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var fetched map[string]interface{}
	decodeJSON(t, resp, &fetched)
	require.Equal(t, "Updated Doc", fetched["title"])
	require.Equal(t, "https://updated.example.com", fetched["url"])
	require.Equal(t, "updated description", fetched["description"])
}

func TestExtended_HealthCheck_WithDB(t *testing.T) {
	server, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + "/api/v1/health")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, resp, &result)

	status, ok := result["status"].(string)
	require.True(t, ok)
	require.Equal(t, "ok", status)

	dbStatus, ok := result["db"].(string)
	require.True(t, ok)
	require.Equal(t, "ok", dbStatus)

	version, ok := result["version"].(string)
	require.True(t, ok)
	// Tests build without ldflags, so version.Version is the default "dev".
	// Release builds inject the real version via -ldflags "-X .../version.Version=v0.1.0".
	require.Equal(t, "dev", version)
}

func TestExtended_DocumentPagination(t *testing.T) {
	server, db := setupExtendedTestServer(t)
	insertTestAdmin(t, db)
	token := loginAsAdmin(t, server)

	for i := 0; i < 5; i++ {
		body := `{"title":"Doc-` + string(rune('A'+i)) + `","type":"url","url":"https://example.com/` + string(rune('A'+i)) + `","description":"doc"}`
		resp := authPost(t, server.URL+"/api/v1/documents", token, body)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		readBody(t, resp)
	}

	resp := authGet(t, server.URL+"/api/v1/documents?limit=2&offset=0", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var page1 map[string]interface{}
	decodeJSON(t, resp, &page1)
	docs1, ok := page1["documents"].([]interface{})
	require.True(t, ok)
	require.Len(t, docs1, 2, "page 1 should return 2 documents")

	resp = authGet(t, server.URL+"/api/v1/documents?limit=2&offset=2", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var page2 map[string]interface{}
	decodeJSON(t, resp, &page2)
	docs2, ok := page2["documents"].([]interface{})
	require.True(t, ok)
	require.Len(t, docs2, 2, "page 2 should return 2 documents")

	title1 := docs1[0].(map[string]interface{})["title"].(string)
	title2 := docs2[0].(map[string]interface{})["title"].(string)
	require.NotEqual(t, title1, title2, "different pages should return different documents")

	resp = authGet(t, server.URL+"/api/v1/documents?limit=2&offset=4", token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var page3 map[string]interface{}
	decodeJSON(t, resp, &page3)
	docs3, ok := page3["documents"].([]interface{})
	require.True(t, ok)
	require.Len(t, docs3, 1, "page 3 should return the last remaining document")
}

func toInt(v interface{}) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}
