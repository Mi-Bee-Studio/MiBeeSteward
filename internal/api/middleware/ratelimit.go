// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter provides per-IP token bucket rate limiting.
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

// NewRateLimiter creates a new RateLimiter with the given rate (requests per second) and burst.
func NewRateLimiter(r float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate.Limit(r),
		burst:    burst,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if v, exists := rl.visitors[ip]; exists {
		v.lastSeen = time.Now()
		return v.limiter
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.visitors[ip] = &visitor{limiter: limiter, lastSeen: time.Now()}
	return limiter
}

func (rl *RateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware returns an HTTP middleware that rate limits requests per IP.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		limiter := rl.getVisitor(ip)

		if !limiter.Allow() {
			slog.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// --- ScanRateLimiter: per-IP sliding window for scan endpoints ---

// ScanRateLimiter provides per-IP sliding window rate limiting for scan operations.
// Uses only stdlib (no external dependencies). Limit is requests per minute.
type ScanRateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time // IP -> sliding window timestamps
	limit   int                    // max requests per window
	window  time.Duration          // sliding window duration
}

// NewScanRateLimiter creates a ScanRateLimiter with the given limit per minute.
func NewScanRateLimiter(limit int) *ScanRateLimiter {
	if limit <= 0 {
		limit = 10
	}
	srl := &ScanRateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
		window:  1 * time.Minute,
	}
	go srl.cleanup()
	return srl
}

// Allow checks if the given IP is within the rate limit.
// It prunes expired entries and returns true if under the limit.
// It prunes expired entries and returns true if under the limit.
func (srl *ScanRateLimiter) Allow(ip string) bool {
	srl.mu.Lock()
	defer srl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-srl.window)

	window := srl.windows[ip]

	// Prune expired entries
	valid := make([]time.Time, 0, len(window))
	for _, t := range window {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	// Check limit
	if len(valid) >= srl.limit {
		srl.windows[ip] = valid
		return false
	}

	// Add current timestamp
	valid = append(valid, now)
	srl.windows[ip] = valid
	return true
}

// cleanup periodically removes stale entries for IPs with no recent activity.
func (srl *ScanRateLimiter) cleanup() {
	for {
		time.Sleep(2 * time.Minute)
		srl.mu.Lock()
		cutoff := time.Now().Add(-2 * srl.window)
		for ip, window := range srl.windows {
			if len(window) > 0 && window[len(window)-1].Before(cutoff) {
				delete(srl.windows, ip)
			}
		}
		srl.mu.Unlock()
	}
}

// Middleware returns an HTTP middleware that rate limits scan operations per IP.
func (srl *ScanRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		if !srl.Allow(ip) {
			slog.Warn("scan rate limit exceeded", "ip", ip, "path", r.URL.Path)
			w.Header().Set("Retry-After", "60")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"scan rate limit exceeded, retry after 60 seconds"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func extractIP(r *http.Request) string {
	// Only trust X-Forwarded-For/X-Real-IP if request comes from localhost (nginx proxy)
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	if remoteIP == "127.0.0.1" || remoteIP == "::1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ip := strings.TrimSpace(strings.Split(xff, ",")[0]); ip != "" {
				return ip
			}
		}
		if rip := r.Header.Get("X-Real-IP"); rip != "" {
			return rip
		}
	}

	return remoteIP
}
