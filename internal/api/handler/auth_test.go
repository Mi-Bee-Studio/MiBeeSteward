package handler_test

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/config"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// --- Cookie Auth Tests ---

func TestAuth_CookieLogin(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	body := `{"username":"admin","password":"admin123"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cookies := resp.Cookies()
	require.NotEmpty(t, cookies, "response should set at least one cookie")

	var tokenCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "token" {
			tokenCookie = c
			break
		}
	}
	require.NotNil(t, tokenCookie, "response should set a cookie named 'token'")
	require.True(t, tokenCookie.HttpOnly, "cookie should be HttpOnly")
	require.Equal(t, "/", tokenCookie.Path, "cookie path should be /")
	require.Equal(t, http.SameSiteStrictMode, tokenCookie.SameSite, "cookie should have SameSite=Strict")
	require.NotEmpty(t, tokenCookie.Value, "cookie value should contain the JWT token")
}

func TestAuth_CookieAuth(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	// Login and extract the Set-Cookie value
	body := `{"username":"admin","password":"admin123"}`
	resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)

	var tokenCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "token" {
			tokenCookie = c
			break
		}
	}
	resp.Body.Close()
	require.NotNil(t, tokenCookie)

	// Use cookie-only auth (no Bearer header) to access a protected endpoint
	req, err := http.NewRequest("GET", server.URL+"/api/v1/auth/profile", nil)
	require.NoError(t, err)
	req.AddCookie(tokenCookie)

	profileResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer profileResp.Body.Close()

	require.Equal(t, http.StatusOK, profileResp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, profileResp, &result)
	require.Equal(t, "admin", result["username"])
}

func TestAuth_Logout(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	// Login to get token and cookie
	token := loginAsAdmin(t, server)

	// Call logout using Bearer token (logout route has no RequireAuth middleware,
	// but the handler reads context if available)
	logoutResp := authPost(t, server.URL+"/api/v1/auth/logout", token, "")
	defer logoutResp.Body.Close()
	require.Equal(t, http.StatusOK, logoutResp.StatusCode)

	// Verify the cookie is cleared (MaxAge=-1)
	cookies := logoutResp.Cookies()
	var tokenCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "token" {
			tokenCookie = c
			break
		}
	}
	require.NotNil(t, tokenCookie, "logout should set a token cookie to clear it")
	require.Equal(t, -1, tokenCookie.MaxAge, "cleared cookie should have MaxAge=-1")
	require.Empty(t, tokenCookie.Value, "cleared cookie should have empty value")

	// Verify subsequent request with the old token still works
	// (JWT is stateless — server doesn't invalidate issued tokens)
	// This is expected behavior; cookie clearing is client-side.
}

// --- CSRF Tests ---

// setupCSRFTestServer creates a test server with CSRF middleware applied.
func setupCSRFTestServer(t *testing.T) (*httptest.Server, *sql.DB) {
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

	middleware.SetJWTAuth(cfg.Auth.JWTSecret)

	expiry := 1 * time.Hour
	userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry)
	auditRepo := repository.NewAuditRepository(db)
	userHandler := handler.NewUserHandler(userSvc, cfg, auditRepo, nil)

	deviceRepo := repository.NewDeviceRepository(db)
	deviceSvc := service.NewDeviceService(deviceRepo, nil)
	deviceHandler := handler.NewDeviceHandler(deviceSvc)

	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(middleware.CSRF) // CSRF middleware applied

	r.Mount("/api/v1/auth", userHandler.Routes())

	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", deviceHandler.Create)
		})
	})

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })

	return server, db
}

func TestAuth_CSRF_BlockedOrigin(t *testing.T) {
	server, db := setupCSRFTestServer(t)
	insertTestAdmin(t, db)

	token := loginAsAdmin(t, server)

	// POST to a protected endpoint with a cross-origin Origin
	req, err := http.NewRequest("POST", server.URL+"/api/v1/devices", bytes.NewBufferString(`{"name":"evil"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.com")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	var result map[string]interface{}
	decodeJSON(t, resp, &result)
	require.Contains(t, result["error"], "forbidden origin")
}

func TestAuth_CSRF_SameOrigin(t *testing.T) {
	server, db := setupCSRFTestServer(t)
	insertTestAdmin(t, db)

	token := loginAsAdmin(t, server)

	// Extract host from server URL to build matching Origin
	serverURL := server.URL
	host := strings.TrimPrefix(serverURL, "http://")

	// POST with same-origin Origin (matching the server's host)
	req, err := http.NewRequest("POST", server.URL+"/api/v1/devices", bytes.NewBufferString(`{"name":"test-device","type":"pc","ip_address":"10.0.0.1"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+host)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should NOT be blocked by CSRF (201 Created or other non-403 code)
	require.NotEqual(t, http.StatusForbidden, resp.StatusCode, "same-origin request should not be blocked by CSRF")
}

// --- Expired Token Test ---

func TestAuth_ExpiredToken(t *testing.T) {
	server, db := setupTestServer(t)
	insertTestAdmin(t, db)

	// Create an expired JWT token manually
	ta := middleware.GetJWTAuth()
	require.NotNil(t, ta)

	claims := map[string]interface{}{
		"user_id":  float64(1),
		"username": "admin",
		"role":     "admin",
	}
	// Set expiry to 1 hour ago to create an already-expired token
	jwtauth.SetExpiry(claims, time.Now().Add(-1*time.Hour))
	_, tokenString, err := ta.Encode(claims)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Try accessing a protected endpoint with the expired token
	resp := authGet(t, server.URL+"/api/v1/auth/profile", tokenString)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- Rate Limit Test ---

// setupRateLimitTestServer creates a test server with login rate limiting applied.
func setupRateLimitTestServer(t *testing.T) *httptest.Server {
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

	middleware.SetJWTAuth(cfg.Auth.JWTSecret)

	expiry := 1 * time.Hour
	userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry)
	auditRepo := repository.NewAuditRepository(db)
	userHandler := handler.NewUserHandler(userSvc, cfg, auditRepo, nil)

	// Rate limiter matching production config: 10 req/min with burst 10
	loginLimiter := middleware.NewRateLimiter(10.0/60.0, 10)

	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(loginLimiter.Middleware)

	r.Mount("/api/v1/auth", userHandler.Routes())

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })

	return server
}

func TestAuth_RateLimit_Login(t *testing.T) {
	server := setupRateLimitTestServer(t)

	// Send 15 login requests rapidly; one should be rate-limited after burst (10) is exhausted
	body := `{"username":"admin","password":"wrong"}`
	got429 := false
	for i := 0; i < 15; i++ {
		resp, err := http.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(body))
		require.NoError(t, err)

		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			bodyStr := readBody(t, resp)
			require.Contains(t, bodyStr, "rate limit")
			break
		}
		// Not rate-limited yet; drain and close body
		io.ReadAll(resp.Body)
		resp.Body.Close()

		// Should be auth errors (401 or 400) before rate limit kicks in
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusBadRequest}, resp.StatusCode,
			"requests before rate limit should return auth errors")
	}

	require.True(t, got429, "should receive 429 Too Many Requests after exceeding rate limit")
}
