package notification

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// mockLogCreator records notification log calls without a real DB.
// Called concurrently from dispatcher workers, so logs is mutex-guarded
// (count uses an atomic for lock-free reads).
type mockLogCreator struct {
	logsMu sync.Mutex
	logs   []db.CreateNotificationLogParams
	mu     atomic.Int32
}

func (m *mockLogCreator) CreateNotificationLog(_ context.Context, arg db.CreateNotificationLogParams) (db.NotificationLog, error) {
	m.mu.Add(1)
	m.logsMu.Lock()
	m.logs = append(m.logs, arg)
	id := int64(len(m.logs))
	m.logsMu.Unlock()
	return db.NotificationLog{ID: id}, nil
}

func (m *mockLogCreator) count() int {
	return int(m.mu.Load())
}

// snapshot returns a copy of the recorded logs; safe to call concurrently
// with CreateNotificationLog.
func (m *mockLogCreator) snapshot() []db.CreateNotificationLogParams {
	m.logsMu.Lock()
	defer m.logsMu.Unlock()
	out := make([]db.CreateNotificationLogParams, len(m.logs))
	copy(out, m.logs)
	return out
}

// mockSender records calls and returns configurable results.
type mockSender struct {
	sendCount atomic.Int32
	result    SendResult
}

func (m *mockSender) Send(_ context.Context, _ Payload) SendResult {
	m.sendCount.Add(1)
	return m.result
}

func TestDispatchNonBlocking(t *testing.T) {
	logMock := &mockLogCreator{}
	d := NewDispatcher(logMock, nil)
	d.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
		return &mockSender{result: SendResult{Success: true}}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop()

	// Dispatch should return immediately
	start := time.Now()
	for i := 0; i < 10; i++ {
		d.Dispatch(ctx, domain.ChannelTypeWebhook, json.RawMessage(`{}`), Payload{
			Subject:   "test",
			Body:      "body",
			Recipient: "http://localhost",
		}, nil, int64(i))
	}
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 100*time.Millisecond, "Dispatch should be non-blocking")

	// Wait for workers to process
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 10, logMock.count(), "all 10 notifications should be logged")
}

func TestWorkerProcessesJob(t *testing.T) {
	logMock := &mockLogCreator{}
	var called atomic.Bool
	d := NewDispatcher(logMock, nil)
	d.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
		return &mockSender{result: SendResult{Success: true}}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop()

	d.Dispatch(ctx, domain.ChannelTypeWebhook, json.RawMessage(`{}`), Payload{
		Subject:   "test subject",
		Body:      "test body",
		Recipient: "test@example.com",
	}, nil, 1)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)
	assert.True(t, called.Load() == false || logMock.count() >= 1, "job should be processed")
	require.Equal(t, 1, logMock.count())

	log := logMock.snapshot()[0]
	assert.Equal(t, "sent", log.Status)
	assert.Contains(t, log.Payload, "test subject")
	assert.Equal(t, int64(1), *log.ChannelID)
}

func TestRetryOnFailure(t *testing.T) {
	logMock := &mockLogCreator{}
	callCount := atomic.Int32{}

	d := NewDispatcher(logMock, nil)
	d.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
		// Fail first 2 attempts, succeed on 3rd
		return SenderFunc(func(_ context.Context, _ Payload) SendResult {
			n := callCount.Add(1)
			if n < 3 {
				return SendResult{Success: false, Error: "connection refused"}
			}
			return SendResult{Success: true}
		}), nil
	})

	// Override retry delay for fast tests
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop()

	d.Dispatch(ctx, domain.ChannelTypeWebhook, json.RawMessage(`{}`), Payload{
		Subject: "retry test",
		Body:    "should retry",
	}, nil, 1)

	// Wait for retries (1s + 2s backoff minimum)
	time.Sleep(4 * time.Second)
	assert.Equal(t, 3, int(callCount.Load()), "should have attempted 3 times")
	require.Equal(t, 1, logMock.count())
	assert.Equal(t, "sent", logMock.snapshot()[0].Status)
}

func TestMaxRetriesExhausted(t *testing.T) {
	logMock := &mockLogCreator{}
	callCount := atomic.Int32{}

	d := NewDispatcher(logMock, nil)
	d.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
		// Always fail with retryable error
		return SenderFunc(func(_ context.Context, _ Payload) SendResult {
			callCount.Add(1)
			return SendResult{Success: false, Error: "connection refused"}
		}), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop()

	d.Dispatch(ctx, domain.ChannelTypeWebhook, json.RawMessage(`{}`), Payload{
		Subject: "max retry test",
	}, nil, 2)

	// Wait for all 3 attempts with backoff (1s + 2s)
	time.Sleep(4 * time.Second)
	assert.Equal(t, 3, int(callCount.Load()), "should attempt 3 times total")
	require.Equal(t, 1, logMock.count())
	snap := logMock.snapshot()[0]
	assert.Equal(t, "failed", snap.Status)
	assert.Contains(t, snap.ErrorMessage, "connection refused")
}

func TestPermanentErrorNoRetry(t *testing.T) {
	logMock := &mockLogCreator{}
	callCount := atomic.Int32{}

	d := NewDispatcher(logMock, nil)
	d.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
		return SenderFunc(func(_ context.Context, _ Payload) SendResult {
			callCount.Add(1)
			return SendResult{Success: false, Error: "535 authentication failed"}
		}), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop()

	d.Dispatch(ctx, domain.ChannelTypeEmail, json.RawMessage(`{}`), Payload{
		Subject: "permanent error test",
	}, nil, 3)

	// Should not retry — give enough time for processing
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, 1, int(callCount.Load()), "should only attempt once for permanent errors")
	require.Equal(t, 1, logMock.count())
	assert.Equal(t, "failed", logMock.snapshot()[0].Status)
}

func TestDispatchDropsWhenFull(t *testing.T) {
	logMock := &mockLogCreator{}
	d := NewDispatcher(logMock, nil)
	d.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
		// Use a slow sender that never completes
		return SenderFunc(func(ctx context.Context, _ Payload) SendResult {
			<-ctx.Done()
			return SendResult{Success: false, Error: "cancelled"}
		}), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)
	defer d.Stop()

	// Fill the channel buffer (100)
	for i := 0; i < 200; i++ {
		d.Dispatch(ctx, domain.ChannelTypeWebhook, json.RawMessage(`{}`), Payload{
			Subject: "overflow test",
		}, nil, int64(i))
	}

	time.Sleep(100 * time.Millisecond)
	// Some should be dropped
	droppedCount := 0
	for _, log := range logMock.snapshot() {
		if log.ErrorMessage == "dispatch queue full" {
			droppedCount++
		}
	}
	assert.Greater(t, droppedCount, 0, "some notifications should be dropped when queue is full")

	// Cancel context to unblock workers, then stop
	cancel()
	d.Stop()
}

func TestStopWaitsForWorkers(t *testing.T) {
	logMock := &mockLogCreator{}
	started := make(chan struct{})
	block := make(chan struct{})

	d := NewDispatcher(logMock, nil)
	d.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
		return SenderFunc(func(_ context.Context, _ Payload) SendResult {
			close(started)
			<-block // block until we release
			return SendResult{Success: true}
		}), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	d.Dispatch(ctx, domain.ChannelTypeWebhook, json.RawMessage(`{}`), Payload{
		Subject: "stop test",
	}, nil, 1)

	// Wait for worker to pick up the job
	<-started

	// Stop should block until workers finish
	stopDone := make(chan struct{})
	go func() {
		d.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		t.Fatal("Stop should not return while worker is blocked")
	case <-time.After(200 * time.Millisecond):
		// Good — Stop is waiting
	}

	// Release the worker
	close(block)

	select {
	case <-stopDone:
		// Good — Stop completed after worker finished
	case <-time.After(2 * time.Second):
		t.Fatal("Stop should complete after worker finishes")
	}
}

// SenderFunc is a helper to create a Sender from a function.
type SenderFunc func(ctx context.Context, payload Payload) SendResult

func (f SenderFunc) Send(ctx context.Context, payload Payload) SendResult {
	return f(ctx, payload)
}
