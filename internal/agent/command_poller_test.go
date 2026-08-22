package agent_test

import (
	"context"
	"encoding/json"
	"log/slog"
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
	// scanResult carries the runScan callback's captured args back to the test
	// goroutine via a channel. This is required (not a bare variable + atomic
	// flag) because runScan executes on the poller's internal goroutine — a
	// bare gotTargets/gotTimeout write read here without synchronization is a
	// data race the -race detector flags (CI caught it; local timing hid it).
	type scanResult struct {
		targets    string
		timeoutSec int
	}
	scanCh := make(chan scanResult, 1)
	var executed int32
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

	runScan := func(_ context.Context, targets string, timeoutSec int) (string, error) {
		scanCh <- scanResult{targets: targets, timeoutSec: timeoutSec}
		return `{"run_id":1}`, nil
	}
	// networkCIDR matches the command's targets so the Layer 2-agent boundary
	// check (issue #19) allows the scan through.
	p := agent.NewCommandPoller(srv.URL, "test-token", 10*time.Millisecond, "192.168.62.0/24", runScan, nil)
	p.Start(context.Background())
	defer p.Stop()

	select {
	case res := <-scanCh:
		require.Equal(t, "192.168.62.0/24", res.targets)
		require.Equal(t, 300, res.timeoutSec)
	case <-time.After(2 * time.Second):
		t.Fatal("poller did not execute the scan command within deadline")
	}
}

// TestCommandPoller_BoundaryCheck_Layer2 covers the agent-side CIDR gate
// (issue #19 Layer 2-agent): a scan command whose targets fall outside this
// agent's own network is rejected before execution — runScan is never called
// and the command completes as "failed".
func TestCommandPoller_BoundaryCheck_Layer2(t *testing.T) {
	t.Run("out-of-network command rejected, runScan not called", func(t *testing.T) {
		var executed int32
		var completeStatus, completeResult string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/agents/commands" && r.Method == http.MethodGet:
				// The exact issue-#19 mis-dispatch: targets=192.168.63.0/24 to an
				// agent whose network is 192.168.62.0/24.
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[{"id":1,"command":"scan","payload":"{\"targets\":\"192.168.63.0/24\",\"timeout\":60}"}]`))
			case r.URL.Path == "/api/v1/agents/commands/1/ack" && r.Method == http.MethodPost:
				w.WriteHeader(http.StatusNoContent)
			case r.URL.Path == "/api/v1/agents/commands/1/complete" && r.Method == http.MethodPost:
				var req struct {
					Status string `json:"status"`
					Result string `json:"result"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				completeStatus = req.Status
				completeResult = req.Result
				atomic.StoreInt32(&executed, 1)
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		runScan := func(context.Context, string, int) (string, error) {
			t.Fatal("runScan must NOT be called for an out-of-network command")
			return "", nil
		}
		p := agent.NewCommandPoller(srv.URL, "test-token", 10*time.Millisecond,
			"192.168.62.0/24", runScan, nil)
		p.Start(context.Background())
		defer p.Stop()

		deadline := time.After(2 * time.Second)
		for atomic.LoadInt32(&executed) != 1 {
			select {
			case <-deadline:
				t.Fatal("poller did not complete the command within deadline")
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
		require.Equal(t, "failed", completeStatus)
		require.Contains(t, completeResult, "out of network")
	})

	t.Run("mixed targets rejected as a whole", func(t *testing.T) {
		var executed int32
		var completeStatus string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/agents/commands" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[{"id":2,"command":"scan","payload":"{\"targets\":\"192.168.62.5,192.168.63.5\",\"timeout\":60}"}]`))
			case r.URL.Path == "/api/v1/agents/commands/2/ack" && r.Method == http.MethodPost:
				w.WriteHeader(http.StatusNoContent)
			case r.URL.Path == "/api/v1/agents/commands/2/complete" && r.Method == http.MethodPost:
				var req struct {
					Status string `json:"status"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				completeStatus = req.Status
				atomic.StoreInt32(&executed, 1)
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		runScan := func(context.Context, string, int) (string, error) {
			t.Fatal("runScan must NOT be called when any target is out of network")
			return "", nil
		}
		p := agent.NewCommandPoller(srv.URL, "test-token", 10*time.Millisecond,
			"192.168.62.0/24", runScan, nil)
		p.Start(context.Background())
		defer p.Stop()

		deadline := time.After(2 * time.Second)
		for atomic.LoadInt32(&executed) != 1 {
			select {
			case <-deadline:
				t.Fatal("poller did not complete the command within deadline")
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
		require.Equal(t, "failed", completeStatus)
	})

	t.Run("no cidr configured → degrade open (scan proceeds)", func(t *testing.T) {
		// An agent without a configured cidr must not lock itself out — the
		// center's Layer 2 check authorizes. Empty cidr → check disabled.
		var executed int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/agents/commands" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[{"id":3,"command":"scan","payload":"{\"targets\":\"10.0.0.1\",\"timeout\":60}"}]`))
			case r.URL.Path == "/api/v1/agents/commands/3/ack" && r.Method == http.MethodPost:
				w.WriteHeader(http.StatusNoContent)
			case r.URL.Path == "/api/v1/agents/commands/3/complete" && r.Method == http.MethodPost:
				atomic.StoreInt32(&executed, 1)
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		runScan := func(context.Context, string, int) (string, error) {
			return `{"run_id":3}`, nil // actually invoked
		}
		// Empty cidr → boundary check disabled.
		p := agent.NewCommandPoller(srv.URL, "test-token", 10*time.Millisecond, "", runScan, nil)
		p.Start(context.Background())
		defer p.Stop()

		deadline := time.After(2 * time.Second)
		for atomic.LoadInt32(&executed) != 1 {
			select {
			case <-deadline:
				t.Fatal("poller did not complete the command within deadline")
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
	})
}

// TestCommandPoller_OpsGatedAndLogsTail covers the remote-ops family (#278):
// disabled poller refuses ops commands; enabled poller serves logs-tail from
// the injected ring. Both via the same fake-center shape as the scan test.
func TestCommandPoller_OpsGatedAndLogsTail(t *testing.T) {
	completeCh := make(chan struct {
		status string
		result string
	}, 2)
	newCenter := func(cmdJSON string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/agents/commands" && r.Method == http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(cmdJSON))
			case r.URL.Path == "/api/v1/agents/commands/1/ack" && r.Method == http.MethodPost:
				w.WriteHeader(http.StatusNoContent)
			case r.URL.Path == "/api/v1/agents/commands/1/complete" && r.Method == http.MethodPost:
				var req struct {
					Status string `json:"status"`
					Result string `json:"result"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				completeCh <- struct {
					status string
					result string
				}{req.Status, req.Result}
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	}

	// 1) ops disabled: logs-tail must fail with the disable reason.
	srv := newCenter(`[{"id":1,"command":"logs-tail","payload":"{}"}]`)
	p := agent.NewCommandPoller(srv.URL, "tok", 60*time.Second, "", nil, nil)
	p.PollOnceForTest(context.Background())
	res := <-completeCh
	require.Equal(t, "failed", res.status)
	require.Contains(t, res.result, "remote ops commands are disabled")
	srv.Close()

	// 2) ops enabled with a ring: logs-tail returns the ring lines as JSON.
	srv2 := newCenter(`[{"id":1,"command":"logs-tail","payload":"{}"}]`)
	ring := agent.NewLogRing(nil, 10)
	require.NoError(t, ring.Handle(context.Background(), slog.Record{
		Level: slog.LevelInfo, Message: "agent booted"}))
	p2 := agent.NewCommandPoller(srv2.URL, "tok", 60*time.Second, "", nil, nil)
	p2.EnableRemoteOps(ring.Lines, nil)
	p2.PollOnceForTest(context.Background())
	res2 := <-completeCh
	require.Equal(t, "done", res2.status)
	require.Contains(t, res2.result, "agent booted")
	srv2.Close()
}
