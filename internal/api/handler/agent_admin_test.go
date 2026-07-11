package handler_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// setupAgentAdminServer builds a minimal server with the agent-token admin
// CRUD routes (no auth middleware — tested directly) over an in-memory DB with
// one pre-seeded network. Returns the server, the db conn, and the network id.
func setupAgentAdminServer(t *testing.T) (srv *httptest.Server, dbConn *sql.DB, networkID int64) {
	t.Helper()
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })

	queries := sqldb.New(dbConn)
	net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{Name: "lan-test"})
	require.NoError(t, err)
	networkID = net.ID

	adm := handler.NewAgentAdminHandler(queries)
	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Route("/api/v1/agents/tokens", func(r chi.Router) {
		r.Post("/", adm.Create)
		r.Get("/", adm.List)
		r.Post("/{id}/revoke", adm.Revoke)
		r.Delete("/{id}", adm.Delete)
	})
	srv = httptest.NewServer(r)
	t.Cleanup(func() { srv.Close() })
	return srv, dbConn, networkID
}

func createToken(t *testing.T, srv *httptest.Server, agentID string, networkID int64) (token string, id int64) {
	t.Helper()
	body, _ := json.Marshal(domain.CreateAgentTokenRequest{AgentID: agentID, NetworkID: networkID, Name: "test"})
	resp, err := http.Post(srv.URL+"/api/v1/agents/tokens", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var out domain.AgentTokenCreatedResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out.Token, out.ID
}

func getNetworkAgentID(t *testing.T, dbConn *sql.DB, networkID int64) string {
	t.Helper()
	var agentID sql.NullString
	err := dbConn.QueryRow(`SELECT agent_id FROM networks WHERE id = ?`, networkID).Scan(&agentID)
	require.NoError(t, err)
	if !agentID.Valid {
		return ""
	}
	return agentID.String
}

// TestAgentAdmin_CreateSetsNetworkAgentID verifies that creating a token
// automatically stamps the network's agent_id — this is what makes the
// heartbeat exclusion + lease sweeper scope engage without manual SQL.
func TestAgentAdmin_CreateSetsNetworkAgentID(t *testing.T) {
	srv, dbConn, netID := setupAgentAdminServer(t)

	require.Equal(t, "", getNetworkAgentID(t, dbConn, netID), "network starts without agent_id")

	_, _ = createToken(t, srv, "agent-test-01", netID)

	require.Equal(t, "agent-test-01", getNetworkAgentID(t, dbConn, netID),
		"creating a token must stamp the network's agent_id")
}

// TestAgentAdmin_RevokeClearsNetworkAgentID verifies that revoking a token
// clears the network's agent_id (so the center resumes local probing for that
// network — the agent is no longer reporting).
func TestAgentAdmin_RevokeClearsNetworkAgentID(t *testing.T) {
	srv, dbConn, netID := setupAgentAdminServer(t)

	_, id := createToken(t, srv, "agent-test-02", netID)
	require.Equal(t, "agent-test-02", getNetworkAgentID(t, dbConn, netID))

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/tokens/"+strconv.FormatInt(id, 10)+"/revoke", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	require.Equal(t, "", getNetworkAgentID(t, dbConn, netID),
		"revoking the token must clear the network's agent_id")
}

// TestAgentAdmin_DeleteClearsNetworkAgentID verifies that deleting a token
// also clears the network's agent_id.
func TestAgentAdmin_DeleteClearsNetworkAgentID(t *testing.T) {
	srv, dbConn, netID := setupAgentAdminServer(t)

	_, id := createToken(t, srv, "agent-test-03", netID)
	require.Equal(t, "agent-test-03", getNetworkAgentID(t, dbConn, netID))

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/agents/tokens/"+strconv.FormatInt(id, 10), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	require.Equal(t, "", getNetworkAgentID(t, dbConn, netID),
		"deleting the token must clear the network's agent_id")
}

// TestAgentAdmin_RevokeDoesNotClobberNewerToken verifies the guard: if a newer
// token with a DIFFERENT agent_id has since claimed the network, revoking the
// OLD token must NOT clear the network's agent_id (otherwise the newer token's
// network loses its agent-managed scope).
func TestAgentAdmin_RevokeDoesNotClobberNewerToken(t *testing.T) {
	srv, dbConn, netID := setupAgentAdminServer(t)

	// Old token.
	_, oldID := createToken(t, srv, "agent-old", netID)
	require.Equal(t, "agent-old", getNetworkAgentID(t, dbConn, netID))

	// Newer token re-uses the same network with a different agent_id.
	_, _ = createToken(t, srv, "agent-new", netID)
	require.Equal(t, "agent-new", getNetworkAgentID(t, dbConn, netID))

	// Revoke the OLD token — must NOT clear agent_id (it belongs to agent-new now).
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/tokens/"+strconv.FormatInt(oldID, 10)+"/revoke", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	require.Equal(t, "agent-new", getNetworkAgentID(t, dbConn, netID),
		"revoking old token must not clobber the newer token's agent_id")
}
