package handler_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	scannerv2runner "mibee-steward/internal/service/scannerv2/runner"
	"mibee-steward/internal/testutil"
)

// setupAgentIngestServer builds a minimal server with ONLY the /agents/report
// route behind RequireAgentToken, plus a real runner over an in-memory DB. It
// seeds a network and an agent token bound to it, returning the plaintext token
// + the network id so tests can build authenticated requests and assert the
// network the device lands on.
func setupAgentIngestServer(t *testing.T) (srv *httptest.Server, db *sql.DB, token string, networkID int64) {
	t.Helper()
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	queries := sqldb.New(db)
	middleware.SetAgentQueries(queries)
	t.Cleanup(func() { middleware.SetAgentQueries(nil) })

	// Seed a network + an agent token bound to it.
	cidr := "192.168.62.0/24"
	net, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{Name: "lan-62", Cidr: &cidr})
	require.NoError(t, err)
	networkID = net.ID

	plaintext, hash := middleware.GenerateAgentToken()
	_, err = queries.CreateAgentToken(context.Background(), sqldb.CreateAgentTokenParams{
		AgentID: "agent-62", TokenHash: hash, NetworkID: &networkID, Name: "62 subnet agent",
	})
	require.NoError(t, err)
	token = plaintext

	// Real runner: device bridge writes devices/heartbeat_configs against db.
	// engine/heartbeat are nil — ApplyReport only needs the device-bridge path,
	// which uses dbConn directly (heartbeat seeding no-ops when heartbeat is nil).
	rn := scannerv2runner.New(nil, queries, db, nil, 0, nil)
	agentReportHandler := handler.NewAgentReportHandler(rn)

	r := chi.NewMux()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Route("/api/v1/agents", func(r chi.Router) {
		r.Use(middleware.RequireAgentToken)
		r.Post("/report", agentReportHandler.Report)
	})
	srv = httptest.NewServer(r)
	t.Cleanup(func() { srv.Close() })
	return srv, db, token, networkID
}

func postReport(t *testing.T, srv *httptest.Server, token string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	return postReportWithHeader(t, srv, token, "", "", body)
}

// postReportWithHeader is postReport with an extra header set (used to send
// X-Network-State-Hash for the anti-entropy hash-skip tests).
func postReportWithHeader(t *testing.T, srv *httptest.Server, token, header, headerVal string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/agents/report", bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if header != "" {
		req.Header.Set(header, headerVal)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestAgentReport_CreatesDeviceOnAgentNetwork verifies the canonical flow: an
// authenticated agent reports a host, and the center creates the devices row
// tagged with the agent's network_id (from its token, NOT the body).
func TestAgentReport_CreatesDeviceOnAgentNetwork(t *testing.T) {
	srv, db, token, networkID := setupAgentIngestServer(t)

	status, out := postReport(t, srv, token, domain.AgentReport{
		AgentID: "agent-62", NetworkName: "lan-62",
		Hosts: []domain.ReportedHost{
			{IP: "192.168.62.41", Alive: true, MAC: "aa:bb:cc:dd:ee:41", InferredType: "camera", InferredBrand: "hikvision"},
		},
	})
	require.Equal(t, http.StatusOK, status, "body=%v", out)
	require.Equal(t, float64(1), out["added"], "one new device should be added")

	// The device row carries the agent's network_id + normalized MAC.
	var devNetworkID *int64
	var mac string
	err := db.QueryRow(`SELECT network_id, mac_address FROM devices WHERE ip_address = ?`, "192.168.62.41").Scan(&devNetworkID, &mac)
	require.NoError(t, err)
	require.NotNil(t, devNetworkID)
	require.Equal(t, networkID, *devNetworkID, "device must be tagged with the agent's network")
	require.Equal(t, "aa:bb:cc:dd:ee:41", mac)
}

// TestAgentReport_MACPrimaryDedupAcrossNetworks confirms the center merges by
// MAC: the SAME MAC reported under two different agent networks resolves to one
// asset row (the first sighting wins). This is the multi-LAN coexistence rule.
func TestAgentReport_MACPrimaryDedupAcrossNetworks(t *testing.T) {
	srv, db, token, networkID := setupAgentIngestServer(t)
	mac := "aa:bb:cc:dd:ee:99"

	// First report: host 192.168.62.50 with this MAC on lan-62.
	_, _ = postReport(t, srv, token, domain.AgentReport{
		AgentID: "agent-62",
		Hosts:   []domain.ReportedHost{{IP: "192.168.62.50", Alive: true, MAC: mac, InferredType: "camera"}},
	})

	// Now simulate a SECOND agent network on the SAME DB: mint a token bound to
	// a different network and report the same MAC at a different IP.
	queries := sqldb.New(db)
	net2, err := queries.CreateNetwork(context.Background(), sqldb.CreateNetworkParams{Name: "lan-63"})
	require.NoError(t, err)
	plaintext2, hash2 := middleware.GenerateAgentToken()
	_, err = queries.CreateAgentToken(context.Background(), sqldb.CreateAgentTokenParams{
		AgentID: "agent-63", TokenHash: hash2, NetworkID: &net2.ID,
	})
	require.NoError(t, err)

	// Same MAC, different IP (roaming / seen on two LANs).
	_, out := postReport(t, srv, plaintext2, domain.AgentReport{
		AgentID: "agent-63",
		Hosts:   []domain.ReportedHost{{IP: "192.168.63.50", Alive: true, MAC: mac, InferredType: "camera"}},
	})
	// The second report UPDATEd the existing MAC-matched row (not added).
	require.Equal(t, float64(1), out["updated"], "same-MAC host should update the existing row, not add")

	// Still exactly one row for that MAC.
	var n int
	err = db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address = ?`, mac).Scan(&n)
	require.NoError(t, err)
	require.Equal(t, 1, n, "roaming MAC must resolve to a single asset")
	// And it stays tagged with the first network (create-wins; IP refreshed).
	var firstNet *int64
	err = db.QueryRow(`SELECT network_id FROM devices WHERE mac_address = ?`, mac).Scan(&firstNet)
	require.NoError(t, err)
	require.Equal(t, networkID, *firstNet)
}

// TestAgentReport_RejectsMissingToken confirms the ingestion route is gated by
// RequireAgentToken — a request with no Authorization header gets 401.
func TestAgentReport_RejectsMissingToken(t *testing.T) {
	srv, _, _, _ := setupAgentIngestServer(t)
	// Post WITHOUT a token (postReport always sets one; do it raw here).
	b, _ := json.Marshal(domain.AgentReport{Hosts: []domain.ReportedHost{{IP: "1.2.3.4", Alive: true}}})
	resp, err := http.Post(srv.URL+"/api/v1/agents/report", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAgentReport_SkipsDeadAndEmptyIP confirms dead hosts and missing-IP hosts
// are skipped (counted), not inserted.
func TestAgentReport_SkipsDeadAndEmptyIP(t *testing.T) {
	srv, db, token, _ := setupAgentIngestServer(t)
	_, out := postReport(t, srv, token, domain.AgentReport{
		Hosts: []domain.ReportedHost{
			{IP: "", Alive: true},               // no IP → skip
			{IP: "192.168.62.99", Alive: false}, // dead → skip
		},
	})
	require.Equal(t, float64(2), out["skipped"])
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n)
	require.Equal(t, 0, n, "no devices should be inserted for skipped hosts")
}

// TestAgentReport_HashSkip_StableNetwork verifies the anti-entropy fast path:
// when the same X-Network-State-Hash arrives twice, the second report skips the
// device bridge entirely (accepted=0, stable=true) — only the lease is refreshed.
func TestAgentReport_HashSkip_StableNetwork(t *testing.T) {
	srv, db, token, _ := setupAgentIngestServer(t)
	host := domain.ReportedHost{IP: "192.168.62.41", Alive: true, MAC: "aa:bb:cc:dd:ee:41", InferredType: "camera"}
	hash := "stable-hash-abc"

	// First report with the hash → full processing (device created).
	status, out := postReportWithHeader(t, srv, token, "X-Network-State-Hash", hash, domain.AgentReport{
		AgentID: "agent-62", Hosts: []domain.ReportedHost{host},
	})
	require.Equal(t, http.StatusOK, status, "body=%v", out)
	require.Equal(t, float64(1), out["added"], "first report adds the device")

	// Second report, SAME hash → should skip (stable=true, accepted=0).
	status2, out2 := postReportWithHeader(t, srv, token, "X-Network-State-Hash", hash, domain.AgentReport{
		AgentID: "agent-62", Hosts: []domain.ReportedHost{host},
	})
	require.Equal(t, http.StatusOK, status2, "body=%v", out2)
	require.Equal(t, true, out2["stable"], "second identical-hash report should be marked stable")
	require.Equal(t, float64(0), out2["accepted"], "stable report should skip the device bridge")

	// Still exactly one device (no duplicate created).
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address='192.168.62.41'`).Scan(&n)
	require.Equal(t, 1, n, "stable report must not create a duplicate device")
}

// TestAgentReport_HashSkip_ChangedNetwork verifies that when the hash CHANGES
// (network state changed), the handler does full processing and caches the new hash.
func TestAgentReport_HashSkip_ChangedNetwork(t *testing.T) {
	srv, db, token, _ := setupAgentIngestServer(t)

	// First report: one host, hash A.
	postReportWithHeader(t, srv, token, "X-Network-State-Hash", "hash-A", domain.AgentReport{
		AgentID: "agent-62",
		Hosts:   []domain.ReportedHost{{IP: "192.168.62.41", Alive: true, MAC: "aa:bb:cc:dd:ee:41", InferredType: "camera"}},
	})

	// Second report: a NEW host appears → hash B (different). Full processing.
	status, out := postReportWithHeader(t, srv, token, "X-Network-State-Hash", "hash-B", domain.AgentReport{
		AgentID: "agent-62",
		Hosts: []domain.ReportedHost{
			{IP: "192.168.62.41", Alive: true, MAC: "aa:bb:cc:dd:ee:41", InferredType: "camera"},
			{IP: "192.168.62.42", Alive: true, MAC: "aa:bb:cc:dd:ee:42", InferredType: "server"},
		},
	})
	require.Equal(t, http.StatusOK, status, "body=%v", out)
	require.Equal(t, float64(1), out["added"], "changed network should process fully (new host 42 added)")
	require.NotEqual(t, true, out["stable"], "changed network should NOT be marked stable")

	// Third report: same hash B → now stable skip.
	_, out3 := postReportWithHeader(t, srv, token, "X-Network-State-Hash", "hash-B", domain.AgentReport{
		AgentID: "agent-62",
		Hosts: []domain.ReportedHost{
			{IP: "192.168.62.41", Alive: true, MAC: "aa:bb:cc:dd:ee:41", InferredType: "camera"},
			{IP: "192.168.62.42", Alive: true, MAC: "aa:bb:cc:dd:ee:42", InferredType: "server"},
		},
	})
	require.Equal(t, true, out3["stable"], "same hash again → stable skip")

	// Two devices total.
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n)
	require.Equal(t, 2, n, "exactly two devices after changed-network sequence")
}
