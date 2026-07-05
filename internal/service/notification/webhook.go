package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// WebhookConfig holds webhook parameters parsed from JSON channel config.
type WebhookConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

// WebhookSender sends notifications via HTTP POST to a webhook endpoint.
type WebhookSender struct {
	Client *http.Client
}

// NewWebhookSender creates a WebhookSender with a 10-second timeout.
func NewWebhookSender() *WebhookSender {
	return &WebhookSender{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// NewWebhookSenderFromConfig creates a WebhookSender (config is parsed per-send, client is shared).
func NewWebhookSenderFromConfig(_ json.RawMessage) (*WebhookSender, error) {
	return NewWebhookSender(), nil
}

// Send delivers a notification via HTTP POST to the URL specified in the channel config.
// The config JSON must contain: {"url": "https://...", "headers": {"X-Custom": "value"}}
func (w *WebhookSender) Send(_ context.Context, _ Payload) SendResult {
	// config is embedded in payload metadata as a workaround — but actually
	// the dispatcher handles config parsing. This method receives payload only.
	// The actual URL and headers come from the dispatcher via the webhook-specific send.
	return SendResult{Success: false, Error: "use SendWithConfig instead"}
}

// SendWithConfig delivers a notification via HTTP POST using the provided webhook config.
func (w *WebhookSender) SendWithConfig(ctx context.Context, payload Payload, config json.RawMessage) SendResult {
	var cfg WebhookConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return SendResult{Success: false, Error: fmt.Sprintf("invalid webhook config: %v", err)}
	}
	if cfg.URL == "" {
		return SendResult{Success: false, Error: "webhook URL is required"}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return SendResult{Success: false, Error: fmt.Sprintf("failed to marshal payload: %v", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return SendResult{Success: false, Error: fmt.Sprintf("failed to create request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := w.Client.Do(req)
	if err != nil {
		slog.Error("webhook send failed", "url", cfg.URL, "error", err)
		return SendResult{Success: false, Error: err.Error()}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Info("webhook sent", "url", cfg.URL, "status", resp.StatusCode)
		return SendResult{Success: true}
	}

	msg := fmt.Sprintf("webhook returned status %d", resp.StatusCode)
	if len(respBody) > 0 {
		msg = fmt.Sprintf("%s: %s", msg, string(respBody))
	}
	slog.Error("webhook failed", "url", cfg.URL, "status", resp.StatusCode)
	return SendResult{Success: false, Error: msg}
}
