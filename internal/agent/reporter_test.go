package agent_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/agent"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
)

// TestReporter_FlushesToCenter verifies the reporter buffers scan results and
// POSTs them to the center on flush (ticker), with the agent's bearer token.
func TestReporter_FlushesToCenter(t *testing.T) {
	var (
		gotAuth  string
		gotBody  domain.AgentReport
		requests int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":1,"added":1}`))
	}))
	defer srv.Close()

	r := agent.NewReporter(srv.URL, "test-token", "agent-x", 20*time.Millisecond, 256, nil)
	r.Start(context.Background())
	// Feed one alive host via the ReportSink hook.
	r.Report(context.Background(), 1, []scannerv2.HostReport{
		{IP: "10.0.0.5", Alive: true, RTTMs: 3, Device: scannerv2.DeviceRef{
			IP: "10.0.0.5", Fields: map[string]string{"inferred_type": "server", "mac": "aa:bb:cc:dd:ee:05"},
		}},
	})

	// Wait for the ticker flush (≤ ~80ms with 20ms interval).
	deadline := time.After(500 * time.Millisecond)
	for {
		if atomic.LoadInt32(&requests) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reporter did not flush within deadline")
		case <-time.After(5 * time.Millisecond):
		}
	}
	r.Stop()

	require.Equal(t, "Bearer test-token", gotAuth, "agent token must be sent as Bearer")
	require.Equal(t, "agent-x", gotBody.AgentID)
	require.Len(t, gotBody.Hosts, 1)
	require.Equal(t, "10.0.0.5", gotBody.Hosts[0].IP)
	require.Equal(t, "server", gotBody.Hosts[0].InferredType)
	require.Equal(t, "aa:bb:cc:dd:ee:05", gotBody.Hosts[0].MAC, "MAC carried through from Device.Fields")
}

// TestReporter_RetriesOn5xx verifies the reporter retries with backoff when the
// center returns a 5xx, then succeeds once the center recovers.
func TestReporter_RetriesOn5xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway) // first two fail
			return
		}
		w.WriteHeader(http.StatusOK) // third succeeds
	}))
	defer srv.Close()

	r := agent.NewReporter(srv.URL, "tok", "a", time.Minute, 1, nil) // maxBuf=1 → immediate flush
	r.Start(context.Background())
	r.Report(context.Background(), 1, []scannerv2.HostReport{{IP: "1.1.1.1", Alive: true, Device: scannerv2.DeviceRef{IP: "1.1.1.1"}}})

	deadline := time.After(60 * time.Second)
	for atomic.LoadInt32(&attempts) < 3 {
		select {
		case <-deadline:
			t.Fatalf("reporter did not reach attempt 3 (got %d)", atomic.LoadInt32(&attempts))
		case <-time.After(50 * time.Millisecond):
		}
	}
	r.Stop()
	require.GreaterOrEqual(t, atomic.LoadInt32(&attempts), int32(3), "should have retried until success")
}

// TestReporter_DoesNotRetryOn4xx verifies a 4xx (e.g. 401 bad token) is
// terminal — retrying won't fix a bad token, so the batch is dropped.
func TestReporter_DoesNotRetryOn4xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	r := agent.NewReporter(srv.URL, "bad", "a", time.Minute, 1, nil)
	r.Start(context.Background())
	r.Report(context.Background(), 1, []scannerv2.HostReport{{IP: "2.2.2.2", Alive: true, Device: scannerv2.DeviceRef{IP: "2.2.2.2"}}})

	time.Sleep(300 * time.Millisecond) // give it time to (not) retry
	r.Stop()
	require.Equal(t, int32(1), atomic.LoadInt32(&attempts), "4xx should be terminal — exactly one attempt")
}

// TestReporter_DisconnectRecovery verifies a batch that fails while the center
// is down is held in the pending queue and delivered once the center recovers.
// This is the断线补报 (disconnect backfill) guarantee.
func TestReporter_DisconnectRecovery(t *testing.T) {
	// Phase 1: center is DOWN (return 503 on every request).
	down := int32(1)
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&down) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := agent.NewReporter(srv.URL, "tok", "a", time.Minute, 1, nil) // maxBuf=1 → immediate flush
	r.Start(context.Background())
	// Report while center is down → batch fails + retries exhaust → enqueued to pending.
	r.Report(context.Background(), 1, []scannerv2.HostReport{{IP: "9.9.9.9", Alive: true, Device: scannerv2.DeviceRef{IP: "9.9.9.9"}}})

	// Wait for the initial flush attempts to exhaust (4 retries × backoff).
	time.Sleep(20 * time.Second)

	// Phase 2: center recovers. Manually trigger a pending flush.
	atomic.StoreInt32(&down, 0)
	r.FlushPendingForTest()

	require.GreaterOrEqual(t, atomic.LoadInt32(&received), int32(1), "pending batch should be delivered after recovery")
	r.Stop()
}
