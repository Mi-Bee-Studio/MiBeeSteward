package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockResult is a single pre-programmed result for mockProber.
type mockResult struct {
	result *Result
	err    error
}

// mockProber is a controllable mock for testing RetryProber.
type mockProber struct {
	results []mockResult
	calls   int
}

func (m *mockProber) Probe(_ context.Context, _ string, _ time.Duration) (*Result, error) {
	idx := m.calls
	m.calls++
	if idx >= len(m.results) {
		last := m.results[len(m.results)-1]
		return last.result, last.err
	}
	return m.results[idx].result, m.results[idx].err
}

func TestRetryProber_SuccessOnFirstTry(t *testing.T) {
	mock := &mockProber{
		results: []mockResult{
			{result: &Result{Success: true, Latency: 10 * time.Millisecond}, err: nil},
		},
	}
	rp := NewRetryProber(mock, 3, 10*time.Millisecond)

	result, err := rp.Probe(context.Background(), "test", time.Second)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if mock.calls != 1 {
		t.Errorf("expected 1 call, got %d", mock.calls)
	}
}

func TestRetryProber_SuccessAfterRetries(t *testing.T) {
	mock := &mockProber{
		results: []mockResult{
			{result: nil, err: errors.New("network error")},
			{result: nil, err: errors.New("network error")},
			{result: &Result{Success: true, Latency: 5 * time.Millisecond}, err: nil},
		},
	}
	rp := NewRetryProber(mock, 3, 10*time.Millisecond)

	result, err := rp.Probe(context.Background(), "test", time.Second)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if mock.calls != 3 {
		t.Errorf("expected 3 calls, got %d", mock.calls)
	}
}

func TestRetryProber_AllRetriesFail(t *testing.T) {
	mock := &mockProber{
		results: []mockResult{
			{result: nil, err: errors.New("network error")},
			{result: nil, err: errors.New("network error")},
			{result: nil, err: errors.New("network error")},
		},
	}
	rp := NewRetryProber(mock, 3, 10*time.Millisecond)

	result, err := rp.Probe(context.Background(), "test", time.Second)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
	if mock.calls != 3 {
		t.Errorf("expected 3 calls, got %d", mock.calls)
	}
}

func TestHTTPProbe_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	prober := &HTTPProber{}
	result, err := prober.Probe(context.Background(), server.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Latency < 0 {
		t.Error("expected non-negative latency")
	}
	// A successful loopback dial can legitimately measure 0 on Windows (clock
	// granularity rounds sub-millisecond dials down); positivity is only
	// guaranteed on Linux (CI).
}

func TestHTTPProbe_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	prober := &HTTPProber{}
	result, err := prober.Probe(context.Background(), server.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.Success {
		t.Error("expected failure for 500 status")
	}
	if result.ErrorMessage == "" {
		t.Error("expected error message for 500 status")
	}
}

// TestHTTPProbe_UserAgent pins #713: an explicit UserAgent replaces Go's
// default header, while the zero value (heartbeat) keeps the default.
func TestHTTPProbe_UserAgent(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.UserAgent()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if _, err := (&HTTPProber{UserAgent: "probe-test/1"}).Probe(context.Background(), server.URL, 5*time.Second); err != nil {
		t.Fatalf("probe with UserAgent: %v", err)
	}
	if got != "probe-test/1" {
		t.Errorf("UserAgent = %q, want probe-test/1", got)
	}

	if _, err := (&HTTPProber{}).Probe(context.Background(), server.URL, 5*time.Second); err != nil {
		t.Fatalf("probe without UserAgent: %v", err)
	}
	if !strings.HasPrefix(got, "Go-http-client/") {
		t.Errorf("zero-value prober sent %q, want Go's default User-Agent", got)
	}
}

func TestUserAgent(t *testing.T) {
	ua := UserAgent()
	if !strings.HasPrefix(ua, "MiBeeSteward-probe/") || strings.HasPrefix(ua, "Go-http-client") {
		t.Errorf("UserAgent() = %q, want a MiBeeSteward-probe product token", ua)
	}
}

func TestTCPProbe_Success(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	prober := &TCPProber{}
	result, err := prober.Probe(context.Background(), listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Latency < 0 {
		t.Error("expected non-negative latency")
	}
	// A successful loopback dial can legitimately measure 0 on Windows (clock
	// granularity rounds sub-millisecond dials down); positivity is only
	// guaranteed on Linux (CI).
}

func TestTCPProbe_ConnectionRefused(t *testing.T) {
	// Use a port with no listener, connection should be refused.
	prober := &TCPProber{}
	result, err := prober.Probe(context.Background(), "127.0.0.1:1", 2*time.Second)
	if err != nil {
		t.Fatalf("expected no error from Probe (failure is in result), got: %v", err)
	}
	if result.Success {
		t.Error("expected failure")
	}
	if result.ErrorMessage == "" {
		t.Error("expected non-empty error message")
	}
}
