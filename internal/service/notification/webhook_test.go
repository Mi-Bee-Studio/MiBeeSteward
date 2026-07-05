package notification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookSenderSuccess(t *testing.T) {
	var receivedPayload Payload
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		err := json.NewDecoder(r.Body).Decode(&receivedPayload)
		assert.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewWebhookSender()
	config, _ := json.Marshal(WebhookConfig{
		URL:     server.URL,
		Headers: map[string]string{"X-Custom": "test-value"},
	})

	result := sender.SendWithConfig(context.Background(), Payload{
		Subject:   "alert",
		Body:      "device offline",
		Recipient: "admin",
		Metadata:  json.RawMessage(`{"device_id": 1}`),
	}, config)

	assert.True(t, result.Success)
	assert.Equal(t, "alert", receivedPayload.Subject)
	assert.Equal(t, "device offline", receivedPayload.Body)
	assert.Equal(t, "admin", receivedPayload.Recipient)
	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
	assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom"))
}

func TestWebhookSenderFailure5xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	sender := NewWebhookSender()
	config, _ := json.Marshal(map[string]string{"url": server.URL})

	result := sender.SendWithConfig(context.Background(), Payload{
		Subject: "test",
		Body:    "body",
	}, config)

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "500")
	assert.Contains(t, result.Error, "internal error")
}

func TestWebhookSenderTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second) // longer than default 10s timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := &WebhookSender{
		Client: &http.Client{Timeout: 1 * time.Second},
	}
	config, _ := json.Marshal(map[string]string{"url": server.URL})

	result := sender.SendWithConfig(context.Background(), Payload{
		Subject: "timeout test",
	}, config)

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "context deadline exceeded")
}

func TestWebhookSenderInvalidURL(t *testing.T) {
	sender := NewWebhookSender()
	config, _ := json.Marshal(map[string]string{"url": "http://invalid-host.invalid:99999"})

	result := sender.SendWithConfig(context.Background(), Payload{
		Subject: "test",
	}, config)

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Error)
}

func TestWebhookSenderMissingURL(t *testing.T) {
	sender := NewWebhookSender()
	config := json.RawMessage(`{}`)

	result := sender.SendWithConfig(context.Background(), Payload{
		Subject: "test",
	}, config)

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "webhook URL is required")
}

func TestWebhookSenderInvalidConfig(t *testing.T) {
	sender := NewWebhookSender()
	config := json.RawMessage(`{invalid json}`)

	result := sender.SendWithConfig(context.Background(), Payload{
		Subject: "test",
	}, config)

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "invalid webhook config")
}

func TestWebhookSenderCustomHeaders(t *testing.T) {
	var headers http.Header
	callCount := atomic.Int32{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		headers = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender := NewWebhookSender()
	config, _ := json.Marshal(WebhookConfig{
		URL: server.URL,
		Headers: map[string]string{
			"Authorization": "Bearer secret-token",
			"X-Event":       "device.alert",
		},
	})

	result := sender.SendWithConfig(context.Background(), Payload{
		Subject: "custom headers test",
		Body:    "body",
	}, config)

	require.True(t, result.Success)
	assert.Equal(t, "Bearer secret-token", headers.Get("Authorization"))
	assert.Equal(t, "device.alert", headers.Get("X-Event"))
	assert.Equal(t, int32(1), callCount.Load())
}

func TestNewWebhookSenderFromConfig(t *testing.T) {
	sender, err := NewWebhookSenderFromConfig(json.RawMessage(`{"url": "http://example.com"}`))
	require.NoError(t, err)
	assert.NotNil(t, sender)
	assert.NotNil(t, sender.Client)
}
