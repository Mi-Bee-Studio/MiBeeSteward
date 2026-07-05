package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// SMTPConfig holds SMTP connection parameters parsed from JSON channel config.
type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
}

// SMTPSender sends notifications via email using net/smtp (stdlib).
type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// NewSMTPSenderFromConfig creates an SMTPSender from a JSON config blob.
func NewSMTPSenderFromConfig(raw json.RawMessage) (*SMTPSender, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty SMTP config")
	}

	var cfg SMTPConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid SMTP config: %w", err)
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("SMTP from address is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 587
	}

	return &SMTPSender{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: cfg.Username,
		Password: cfg.Password,
		From:     cfg.From,
	}, nil
}

// Send delivers an email notification. The payload.Recipient must be a valid email address.
func (s *SMTPSender) Send(ctx context.Context, payload NotificationPayload) SendResult {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)

	subject := payload.Subject
	if subject == "" {
		subject = "MiBee Steward Notification"
	}

	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString(fmt.Sprintf("From: %s\r\n", s.From))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", payload.Recipient))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(payload.Body)

	// Use PlainAuth if credentials are provided
	var auth smtp.Auth
	if s.Username != "" && s.Password != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}

	err := smtp.SendMail(addr, auth, s.From, []string{payload.Recipient}, msg.Bytes())
	if err != nil {
		slog.Error("SMTP send failed", "recipient", payload.Recipient, "error", err)
		return SendResult{Success: false, Error: err.Error()}
	}

	slog.Info("email sent", "recipient", payload.Recipient, "subject", subject)
	return SendResult{Success: true}
}

// isPermanentSMTPError checks if an SMTP error is permanent (not retryable).
func isPermanentSMTPError(errMsg string) bool {
	lower := strings.ToLower(errMsg)
	permanentCodes := []string{"535", "550", "553", "554", "552"}
	for _, code := range permanentCodes {
		if strings.Contains(lower, code) {
			return true
		}
	}
	permanentWords := []string{"authentication failed", "auth failed", "recipient rejected", "mailbox not found"}
	for _, word := range permanentWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}
