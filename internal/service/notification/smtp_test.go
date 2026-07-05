package notification

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSMTPSenderFromConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
		check   func(*testing.T, *SMTPSender)
	}{
		{
			name:    "valid config",
			config:  `{"host": "smtp.example.com", "port": 587, "username": "user", "password": "pass", "from": "noreply@example.com"}`,
			wantErr: false,
			check: func(t *testing.T, s *SMTPSender) {
				assert.Equal(t, "smtp.example.com", s.Host)
				assert.Equal(t, 587, s.Port)
				assert.Equal(t, "user", s.Username)
				assert.Equal(t, "noreply@example.com", s.From)
			},
		},
		{
			name:    "default port",
			config:  `{"host": "smtp.example.com", "from": "noreply@example.com"}`,
			wantErr: false,
			check: func(t *testing.T, s *SMTPSender) {
				assert.Equal(t, 587, s.Port)
			},
		},
		{
			name:    "empty config",
			config:  ``,
			wantErr: true,
		},
		{
			name:    "missing host",
			config:  `{"from": "noreply@example.com"}`,
			wantErr: true,
		},
		{
			name:    "missing from",
			config:  `{"host": "smtp.example.com"}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			config:  `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, err := NewSMTPSenderFromConfig(json.RawMessage(tt.config))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			tt.check(t, sender)
		})
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name    string
		result  SendResult
		want    bool
	}{
		{"success", SendResult{Success: true}, false},
		{"connection refused", SendResult{Success: false, Error: "connection refused"}, true},
		{"timeout", SendResult{Success: false, Error: "i/o timeout"}, true},
		{"dns error", SendResult{Success: false, Error: "no such host"}, true},
		{"auth failure", SendResult{Success: false, Error: "535 authentication failed"}, false},
		{"recipient invalid", SendResult{Success: false, Error: "550 recipient rejected"}, false},
		{"empty error", SendResult{Success: false}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.IsRetryable())
		})
	}
}

func TestIsPermanentSMTPError(t *testing.T) {
	tests := []struct {
		err  string
		want bool
	}{
		{"connection refused", false},
		{"i/o timeout", false},
		{"535 5.7.8 Authentication failed", true},
		{"550 5.1.1 Recipient rejected", true},
		{"553 mailbox not found", true},
		{"554 relay access denied", true},
		{"552 quota exceeded", true},
	}

	for _, tt := range tests {
		t.Run(tt.err, func(t *testing.T) {
			assert.Equal(t, tt.want, isPermanentSMTPError(tt.err))
		})
	}
}

// Test that SMTPSender.Send returns proper error format on failure
func TestSMTPSenderSendInvalidServer(t *testing.T) {
	sender := &SMTPSender{
		Host:     "invalid-host-that-does-not-exist.invalid",
		Port:     587,
		From:     "test@example.com",
		Username: "user",
		Password: "pass",
	}

	result := sender.Send(context.Background(), NotificationPayload{
		Subject:   "test",
		Body:      "test body",
		Recipient: "recipient@example.com",
	})

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Error)
}
