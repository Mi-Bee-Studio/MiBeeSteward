package middleware

import (
	"net/http"
)

// RequireAuth returns middleware that requires a valid authenticated user.
// If no valid user context is found, it responds with 401 Unauthorized.
func RequireAuth(next http.Handler) http.Handler {
	return Authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := GetUserFromContext(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequireAdmin returns middleware that requires an authenticated admin user.
// If no valid user context is found, it responds with 401 Unauthorized.
// If user is not an admin, it responds with 403 Forbidden.
func RequireAdmin(next http.Handler) http.Handler {
	return Authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, role, ok := GetUserFromContext(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if role != "admin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden: admin access required"}`))
			return
		}
		next.ServeHTTP(w, r)
	}))
}
