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
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/jwtauth/v5"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// TokenAuth is the global JWT authenticator. Set via SetJWTAuth.
var tokenAuth *jwtauth.JWTAuth

// SetJWTAuth initializes the global JWT authenticator with the given secret.
func SetJWTAuth(secret string) {
	tokenAuth = jwtauth.New("HS256", []byte(secret), nil)
}

// tokenBlacklist is the global token blacklist. Set via SetTokenBlacklist.
var tokenBlacklist *service.TokenBlacklist

// SetTokenBlacklist sets the global token blacklist for revocation checks.
func SetTokenBlacklist(bl *service.TokenBlacklist) {
	tokenBlacklist = bl
}

// GetJWTAuth returns the global JWT authenticator.
func GetJWTAuth() *jwtauth.JWTAuth {
	return tokenAuth
}

// Authenticator is middleware that extracts and verifies a JWT from the
// Authorization header, then injects user_id and role into the request context.
func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractToken(r)
		if tokenStr == "" {
			next.ServeHTTP(w, r)
			return
		}

		if tokenAuth == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Verify and validate token (including expiry check)
		tok, err := jwtauth.VerifyToken(tokenAuth, tokenStr)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// Check token blacklist (revoked tokens)
		if tokenBlacklist != nil {
			var jti string
			if err := tok.Get("jti", &jti); err == nil && jti != "" {
				if tokenBlacklist.IsBlacklisted(jti) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		ctx := r.Context()

		// Extract user_id claim
		var userID float64
		if err := tok.Get("user_id", &userID); err == nil {
			ctx = context.WithValue(ctx, domain.ContextKeyUserID, int64(userID))
		}

		// Extract role claim
		var role string
		if err := tok.Get("role", &role); err == nil {
			ctx = context.WithValue(ctx, domain.ContextKeyRole, role)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractToken gets the token from cookie first, then falls back to Authorization header.
func extractToken(r *http.Request) string {
	// 1. Check cookie first
	if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	// 2. Fall back to Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// GetUserFromContext extracts user_id and role from the request context.
func GetUserFromContext(r *http.Request) (userID int64, role string, ok bool) {
	ctx := r.Context()

	idVal := ctx.Value(domain.ContextKeyUserID)
	roleVal := ctx.Value(domain.ContextKeyRole)

	if idVal == nil || roleVal == nil {
		return 0, "", false
	}

	userID, idOk := idVal.(int64)
	role, roleOk := roleVal.(string)

	if !idOk || !roleOk {
		return 0, "", false
	}

	return userID, role, true
}
