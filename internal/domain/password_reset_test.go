package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResetTokenRequest_JSONTags(t *testing.T) {
	req := ResetTokenRequest{
		Email: "user@example.com",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal ResetTokenRequest: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, ok := decoded["email"]; !ok {
		t.Error("missing JSON field \"email\" in ResetTokenRequest")
	}
}

func TestResetPasswordRequest_JSONTags(t *testing.T) {
	req := ResetPasswordRequest{
		Token:       "abc123token",
		NewPassword: "NewP@ss123",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal ResetPasswordRequest: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"token", "new_password"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in ResetPasswordRequest", field)
		}
	}
}

func TestResetTokenResponse_JSONTags(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)
	resp := ResetTokenResponse{
		Token:     "abc123token",
		ExpiresAt: expiresAt,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ResetTokenResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"token", "expires_at"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in ResetTokenResponse", field)
		}
	}
}

func TestResetPasswordResponse_JSONTags(t *testing.T) {
	resp := ResetPasswordResponse{
		Message: "Password reset successfully",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ResetPasswordResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, ok := decoded["message"]; !ok {
		t.Error("missing JSON field \"message\" in ResetPasswordResponse")
	}
}

func TestResetTokenResponse_Values(t *testing.T) {
	expiresAt := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	resp := ResetTokenResponse{
		Token:     "secure-token-123",
		ExpiresAt: expiresAt,
	}

	if resp.Token != "secure-token-123" {
		t.Errorf("Token = %q, want %q", resp.Token, "secure-token-123")
	}
	if !resp.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", resp.ExpiresAt, expiresAt)
	}
}
