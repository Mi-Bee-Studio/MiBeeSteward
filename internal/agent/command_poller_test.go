package agent_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/agent"
)

// TestCommandPoller_ScanPayload_StringQuoted reproduces the center→agent command
// payload mismatch: the center stores payload as a TEXT column and serializes it
// as a JSON STRING (quoted) in the poll response. The poller must unmarshal the
// string body into scanPayload, not fail with "cannot unmarshal string into Go
// value of type agent.scanPayload". This is a regression guard for the fix that
// changed pendingCommand.Payload from json.RawMessage to string.
func TestCommandPoller_ScanPayload_StringQuoted(t *testing.T) {
	var (
		gotTargets string
		gotTimeout int
		executed   int32
	)
	// The center's Poll handler returns []AgentCommand where Payload is a Go
	// string; encoding/json serializes a string field as a JSON string literal
	// (double-quoted), e.g. "payload":"{\"targets\":\"192.168.62.0/24\",\"timeout\":300}".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/agents/commands" && r.Method == http.MethodGet:
			// Two shapes the center can emit, both valid JSON encodings of a
			// TEXT payload field. The string form is what sqlc's string-typed
			// AgentCommand.Payload produces; verify the poller handles it.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1,"command":"scan","payload":"{\"targets\":\"192.168.62.0/24\",\"timeout\":300}"}]`))
		case r.URL.Path == "/api/v1/agents/commands/1/ack" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/agents/commands/1/complete" && r.Method == http.MethodPost:
			var req struct {
				Status string `json:"status"`
				Result string `json:"result"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			require.Equal(t, "done", req.Status, "scan should succeed, not fail with bad-payload")
			atomic.StoreInt32(&executed, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	runScan := func(ctx context.Context, targets string, timeoutSec int) (string, error) {
		gotTargets = targets
		gotTimeout = timeoutSec
		return `{"run_id":1}`, nil
	}
	p := agent.NewCommandPoller(srv.URL, "test-token", 10*time.Millisecond, runScan, nil)
	p.Start(context.Background())
	defer p.Stop()

	deadline := time.After(2 * time.Second)
	for {
		if atomic.LoadInt32(&executed) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("poller did not execute the scan command within deadline")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	require.Equal(t, "192.168.62.0/24", gotTargets)
	require.Equal(t, 300, gotTimeout)
}
