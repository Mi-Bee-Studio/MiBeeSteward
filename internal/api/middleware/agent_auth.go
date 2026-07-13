package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// agentQueries is the DB handle used by RequireAgentToken to look up agent
// tokens. Set once at startup via SetAgentQueries (the ingestion routes are
// registered after DB open, so this is wired in routes.go before the agent
// route group).
var agentQueries *db.Queries

// SetAgentQueries wires the DB querier that RequireAgentToken uses to verify
// agent bearer tokens. Called once during router setup.
func SetAgentQueries(q *db.Queries) {
	agentQueries = q
}

// RequireAgentToken authenticates a discovery agent via an opaque bearer token
// in the Authorization header. This is the machine-to-machine auth path,
// distinct from the human user JWT flow:
//
//   - extracts the bearer token (Authorization: Bearer <opaque>)
//   - hashes it (SHA-256, hex) and looks up agent_tokens.token_hash
//   - rejects (401) on no token / unknown hash / revoked token
//   - on success injects agent_id + network_id into the request context and
//     updates last_used_at (best-effort, non-blocking)
//
// The plaintext token is NEVER stored — only its hash — so lookup is by hash.
func RequireAgentToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if agentQueries == nil {
			http.Error(w, "agent auth not configured", http.StatusInternalServerError)
			return
		}
		tok := extractBearerToken(r)
		if tok == "" {
			http.Error(w, "missing agent token", http.StatusUnauthorized)
			return
		}
		hash := HashAgentToken(tok)

		row, err := agentQueries.GetAgentTokenByHash(r.Context(), hash)
		if err != nil {
			http.Error(w, "invalid agent token", http.StatusUnauthorized)
			return
		}
		if row.RevokedAt != nil {
			http.Error(w, "agent token revoked", http.StatusUnauthorized)
			return
		}
		// Best-effort last-used stamp; a failure here must not fail the request
		// (the lookup above already proved the token is valid).
		_ = agentQueries.TouchAgentTokenLastUsed(r.Context(), row.ID)

		ctx := r.Context()
		ctx = context.WithValue(ctx, domain.ContextKeyAgentID, row.AgentID)
		if row.NetworkID != nil {
			ctx = context.WithValue(ctx, domain.ContextKeyAgentNetworkID, *row.NetworkID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractBearerToken pulls the opaque token from "Authorization: Bearer <tok>".
// Returns "" when the header is absent or malformed. Deliberately separate from
// the JWT extractToken (cookie-first) so the two auth paths can't interfere.
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	// Case-insensitive scheme match (RFC 7235), then trim the prefix.
	if len(h) >= len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// GetAgentFromContext returns the agent_id and network_id injected by
// RequireAgentToken. Handlers on ingestion routes use this to scope writes to
// the agent's network. ok is false when called outside an agent-authed route.
func GetAgentFromContext(r *http.Request) (agentID string, networkID *int64, ok bool) {
	v := r.Context().Value(domain.ContextKeyAgentID)
	aid, _ := v.(string)
	if aid == "" {
		return "", nil, false
	}
	nid, _ := r.Context().Value(domain.ContextKeyAgentNetworkID).(int64)
	if nid > 0 {
		return aid, &nid, true
	}
	return aid, nil, true
}

// HashAgentToken returns the SHA-256 hex digest of the plaintext token. Used
// both at creation (store the hash) and at verification (hash the presented
// token, look up by hash). Exported so the admin handler shares it.
func HashAgentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// GenerateAgentToken returns a freshly-generated opaque token (32 random bytes
// hex-encoded = 64 chars) plus its SHA-256 hash. The plaintext goes to the
// operator once; the hash is what gets stored. Panics only on a crypto/rand
// failure (which indicates a broken host entropy source — not recoverable).
func GenerateAgentToken() (plaintext, hash string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	plaintext = hex.EncodeToString(b)
	hash = HashAgentToken(plaintext)
	return plaintext, hash
}
