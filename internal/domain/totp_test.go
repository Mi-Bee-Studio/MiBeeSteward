package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTOTPSetupRequest_JSONTags(t *testing.T) {
	req := TOTPSetupRequest{
		UserID: 1,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal TOTPSetupRequest: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, ok := decoded["user_id"]; !ok {
		t.Error("missing JSON field \"user_id\" in TOTPSetupRequest")
	}
}

func TestTOTPVerifyRequest_JSONTags(t *testing.T) {
	req := TOTPVerifyRequest{
		UserID: 1,
		Code:   "123456",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal TOTPVerifyRequest: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"user_id", "code"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in TOTPVerifyRequest", field)
		}
	}
}

func TestTOTPEnableRequest_JSONTags(t *testing.T) {
	req := TOTPEnableRequest{
		UserID: 1,
		Code:   "123456",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal TOTPEnableRequest: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"user_id", "code"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in TOTPEnableRequest", field)
		}
	}
}

func TestTOTPSetupResponse_JSONTags(t *testing.T) {
	resp := TOTPSetupResponse{
		Secret:      "JBSWY3DPEHPK3PXP",
		BackupCodes: json.RawMessage(`["code1","code2"]`),
		QRCodeURL:   "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal TOTPSetupResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"secret", "backup_codes", "qr_code_url"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in TOTPSetupResponse", field)
		}
	}
}

func TestTOTPStatusResponse_JSONTags(t *testing.T) {
	resp := TOTPStatusResponse{
		Enabled:   true,
		Verified:  true,
		CreateAt:  time.Now(),
		UpdatedAt: time.Now(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal TOTPStatusResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"enabled", "verified", "created_at", "updated_at"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in TOTPStatusResponse", field)
		}
	}
}

func TestTOTPSetupResponse_Values(t *testing.T) {
	resp := TOTPSetupResponse{
		Secret:    "JBSWY3DPEHPK3PXP",
		QRCodeURL: "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP",
	}

	if resp.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q, want %q", resp.Secret, "JBSWY3DPEHPK3PXP")
	}
	if resp.QRCodeURL != "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP" {
		t.Errorf("QRCodeURL = %q, want %q", resp.QRCodeURL, "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP")
	}
}
