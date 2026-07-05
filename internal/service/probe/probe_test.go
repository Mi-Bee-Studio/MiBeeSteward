package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockResult is a single pre-programmed result for mockProber.
type mockResult struct {
	result *ProbeResult
	err    error
}

// mockProber is a controllable mock for testing RetryProber.
type mockProber struct {
	results []mockResult
	calls   int
}

func (m *mockProber) Probe(_ context.Context, _ string, _ time.Duration) (*ProbeResult, error) {
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
			{result: &ProbeResult{Success: true, Latency: 10 * time.Millisecond}, err: nil},
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
			{result: &ProbeResult{Success: true, Latency: 5 * time.Millisecond}, err: nil},
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
	if result.Latency <= 0 {
		t.Error("expected positive latency")
	}
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
	if result.Latency <= 0 {
		t.Error("expected positive latency")
	}
}

func TestTCPProbe_ConnectionRefused(t *testing.T) {
	// Use a port with no listener — connection should be refused.
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
