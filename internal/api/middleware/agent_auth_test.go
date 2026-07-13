package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// setupAgentAuthDB creates a DB with the agent_tokens + networks tables and a
// seeded network row, wires it into the middleware, and returns the plaintext
// token + its network id for use in test requests.
func setupAgentAuthDB(t *testing.T) (token string, networkID int64) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	queries := db.New(conn)
	middleware.SetAgentQueries(queries)
	t.Cleanup(func() { middleware.SetAgentQueries(nil) })

	// Seed a network so the token's FK is valid.
	cidr := "10.0.0.0/24"
	net, err := queries.CreateNetwork(context.Background(), db.CreateNetworkParams{
		Name: "test-lan", Cidr: &cidr,
	})
	require.NoError(t, err)
	networkID = net.ID

	// Mint a token via the middleware helper and store its hash.
	plaintext, hash := middleware.GenerateAgentToken()
	_, err = queries.CreateAgentToken(context.Background(), db.CreateAgentTokenParams{
		AgentID:   "agent-test",
		TokenHash: hash,
		NetworkID: &networkID,
		Name:      "test agent",
	})
	require.NoError(t, err)
	return plaintext, networkID
}

// do runs a request through RequireAgentToken into a handler that records
// whether it was reached and what agent context it saw.
func do(t *testing.T, token string) (reached bool, agentID string, netID *int64) {
	t.Helper()
	reached = false
	h := middleware.RequireAgentToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		agentID, netID, _ = middleware.GetAgentFromContext(r)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/agents/report", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	h.ServeHTTP(rec, req)
	return reached, agentID, netID
}

func TestRequireAgentToken_ValidTokenPasses(t *testing.T) {
	token, netID := setupAgentAuthDB(t)
	reached, agentID, ctxNet := do(t, token)
	require.True(t, reached, "valid token should reach the handler")
	require.Equal(t, "agent-test", agentID)
	require.NotNil(t, ctxNet)
	require.Equal(t, netID, *ctxNet)
}

func TestRequireAgentToken_MissingTokenRejected(t *testing.T) {
	setupAgentAuthDB(t)
	reached, _, _ := do(t, "")
	require.False(t, reached, "missing token must not reach the handler")
}

func TestRequireAgentToken_InvalidTokenRejected(t *testing.T) {
	setupAgentAuthDB(t)
	reached, _, _ := do(t, "not-a-real-token")
	require.False(t, reached, "unknown token must not reach the handler")
}

func TestRequireAgentToken_RevokedTokenRejected(t *testing.T) {
	// Fresh fixture: seed a network + token, revoke it, then a request with the
	// (still-valid-shaped) token must be rejected.
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	queries := db.New(conn)
	middleware.SetAgentQueries(queries)
	t.Cleanup(func() { middleware.SetAgentQueries(nil) })

	net, err := queries.CreateNetwork(context.Background(), db.CreateNetworkParams{Name: "rev-lan"})
	require.NoError(t, err)
	plaintext, hash := middleware.GenerateAgentToken()
	row, err := queries.CreateAgentToken(context.Background(), db.CreateAgentTokenParams{
		AgentID: "agent-rev", TokenHash: hash, NetworkID: &net.ID,
	})
	require.NoError(t, err)
	n, err := queries.RevokeAgentToken(context.Background(), row.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "token should be revoked")

	reached, _, _ := do(t, plaintext)
	require.False(t, reached, "revoked token must not reach the handler")
}

func TestGenerateAgentToken_HashIsDeterministicAndUnique(t *testing.T) {
	a, hashA := middleware.GenerateAgentToken()
	b, hashB := middleware.GenerateAgentToken()
	require.NotEqual(t, a, b, "two generated tokens must differ")
	require.Equal(t, middleware.HashAgentToken(a), hashA, "hash must be deterministic")
	require.Equal(t, middleware.HashAgentToken(b), hashB)
	require.Equal(t, len(a), 64, "token should be 32 bytes hex = 64 chars")
	// Ensure the context-key constants are distinct (no accidental reuse).
	require.NotEqual(t, domain.ContextKeyAgentID, domain.ContextKeyAgentNetworkID)
}
