package notification

import (
	"context"
	"encoding/json"
)

// Sender defines the interface for sending notifications through a specific channel.
type Sender interface {
	Send(ctx context.Context, payload NotificationPayload) SendResult
}

// NotificationPayload contains the message data to be delivered.
type NotificationPayload struct {
	Subject   string          `json:"subject"`
	Body      string          `json:"body"`
	Recipient string          `json:"recipient"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// SendResult reports the outcome of a send attempt.
type SendResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// IsRetryable returns true if the error represents a transient failure
// (network timeout, connection refused, DNS failure) that warrants retry.
// Permanent errors (auth failure, invalid recipient) should not be retried.
func (r SendResult) IsRetryable() bool {
	if r.Success {
		return false
	}
	msg := r.Error
	if msg == "" {
		return false
	}
	// Permanent errors — do not retry
	if containsAny(msg,
		"authentication",
		"auth",
		"535",
		"550",
		"553",
		"recipient",
		"invalid",
		"malformed",
	) {
		return false
	}
	return true
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
