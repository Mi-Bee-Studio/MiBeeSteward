package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/middleware"
)

// setupScanRateLimitTestServer creates a test server with the scan rate limiter applied.
func setupScanRateLimitTestServer(t *testing.T, limit int) *httptest.Server {
	t.Helper()

	scanLimiter := middleware.NewScanRateLimiter(limit)

	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)

	r.Route("/api/v1/scanner", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(scanLimiter.Middleware)
			r.Post("/scan", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"scan started"}`))
			})
			r.Post("/tasks/{id}/trigger", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"triggered"}`))
			})
		})
		// Non-rate-limited routes
		r.Get("/tasks", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"tasks":[]}`))
		})
	})

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })
	return server
}

func TestScanRateLimit_AllowsRequestsUnderLimit(t *testing.T) {
	server := setupScanRateLimitTestServer(t, 5)

	// Send 5 requests (within the limit of 5 per minute)
	for i := 0; i < 5; i++ {
		resp, err := http.Post(server.URL+"/api/v1/scanner/scan", "application/json", nil)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "request %d should succeed: %s", i+1, string(body))
	}
}

func TestScanRateLimit_BlocksRequestsOverLimit(t *testing.T) {
	// Use a limit of 3 for faster test
	server := setupScanRateLimitTestServer(t, 3)

	got429 := false
	for i := 0; i < 10; i++ {
		resp, err := http.Post(server.URL+"/api/v1/scanner/scan", "application/json", nil)
		require.NoError(t, err)

		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			// Verify Retry-After header
			require.Equal(t, "60", resp.Header.Get("Retry-After"))
			// Verify JSON error body
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.Contains(t, string(body), "scan rate limit exceeded")
			break
		}

		require.Equal(t, http.StatusOK, resp.StatusCode)
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	require.True(t, got429, "should receive 429 Too Many Requests after exceeding rate limit")
}

func TestScanRateLimit_DifferentIPsHaveIndependentLimits(t *testing.T) {
	server := setupScanRateLimitTestServer(t, 3)

	// Exhaust limit for IP 127.0.0.1
	for i := 0; i < 3; i++ {
		resp, err := http.Post(server.URL+"/api/v1/scanner/scan", "application/json", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// Next request from 127.0.0.1 should be blocked
	resp, err := http.Post(server.URL+"/api/v1/scanner/scan", "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)

	// Request from a different IP should succeed (independent limit)
	req, err := http.NewRequest("POST", server.URL+"/api/v1/scanner/scan", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	client := &http.Client{}
	resp2, err := client.Do(req)
	require.NoError(t, err)
	resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "different IP should have its own limit")
}

func TestScanRateLimit_TriggerEndpointAlsoRateLimited(t *testing.T) {
	server := setupScanRateLimitTestServer(t, 2)

	// Exhaust limit via /scan
	resp, err := http.Post(server.URL+"/api/v1/scanner/scan", "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Post(server.URL+"/api/v1/scanner/scan", "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// /tasks/{id}/trigger should also be limited (shared counter)
	resp, err = http.Post(server.URL+"/api/v1/scanner/tasks/1/trigger", "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "trigger should share rate limit with scan")
}

func TestScanRateLimit_NonRateLimitedRoutesAreNotAffected(t *testing.T) {
	server := setupScanRateLimitTestServer(t, 1)

	// Exhaust scan limit
	resp, err := http.Post(server.URL+"/api/v1/scanner/scan", "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// /tasks should not be rate-limited
	resp, err = http.Get(server.URL + "/api/v1/scanner/tasks")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "non-rate-limited routes should not be affected")
}

func TestScanRateLimit_DefaultLimit(t *testing.T) {
	// NewScanRateLimiter with 0 should default to 10
	limiter := middleware.NewScanRateLimiter(0)
	require.NotNil(t, limiter)
	// Just verify it doesn't panic and allows requests
	require.True(t, limiter.Allow("test-ip"), "default limit should allow requests")
}

// Test helper to exercise allow() directly
func TestScanRateLimiter_Allow(t *testing.T) {
	limiter := middleware.NewScanRateLimiter(3)

	// First 3 should be allowed
	require.True(t, limiter.Allow("10.0.0.1"))
	require.True(t, limiter.Allow("10.0.0.1"))
	require.True(t, limiter.Allow("10.0.0.1"))

	// 4th should be blocked
	require.False(t, limiter.Allow("10.0.0.1"))
}
