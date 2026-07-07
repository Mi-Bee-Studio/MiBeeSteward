package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestChannelTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		actual   ChannelType
		expected ChannelType
	}{
		{"ChannelTypeWebhook", ChannelTypeWebhook, "webhook"},
		{"ChannelTypeEmail", ChannelTypeEmail, "email"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.actual != tt.expected {
				t.Errorf("ChannelType = %q, want %q", tt.actual, tt.expected)
			}
		})
	}
}

func TestCreateChannelRequest_JSONTags(t *testing.T) {
	enabled := true
	req := CreateChannelRequest{
		Name:    "Test Channel",
		Type:    ChannelTypeWebhook,
		Config:  json.RawMessage(`{"url":"https://hooks.example.com"}`),
		Enabled: &enabled,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal CreateChannelRequest: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"name", "type", "config", "enabled"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in CreateChannelRequest", field)
		}
	}
}

func TestUpdateChannelRequest_JSONTags(t *testing.T) {
	name := "Updated Channel"
	req := UpdateChannelRequest{
		Name: &name,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal UpdateChannelRequest: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, ok := decoded["name"]; !ok {
		t.Error("missing JSON field \"name\" in UpdateChannelRequest")
	}
	// omitempty should exclude nil pointer fields
	if _, ok := decoded["config"]; ok {
		t.Error("nil pointer field \"config\" should be omitted")
	}
}

func TestChannelResponse_JSONTags(t *testing.T) {
	resp := ChannelResponse{
		ID:        1,
		Name:      "Webhook",
		Type:      "webhook",
		Config:    json.RawMessage(`{}`),
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ChannelResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"id", "name", "type", "config", "enabled", "created_at", "updated_at"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in ChannelResponse", field)
		}
	}
}

func TestNotificationLogResponse_JSONTags(t *testing.T) {
	resp := NotificationLogResponse{
		ID:           1,
		Status:       "sent",
		Payload:      `{"message":"test"}`,
		ErrorMessage: "",
		SentAt:       time.Now(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal NotificationLogResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	expectedFields := []string{"id", "status", "payload", "error_message", "sent_at"}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in NotificationLogResponse", field)
		}
	}
}

func TestChannelListResponse_JSONTags(t *testing.T) {
	resp := ChannelListResponse{
		Channels: []ChannelResponse{},
		Total:    0,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ChannelListResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, ok := decoded["channels"]; !ok {
		t.Error("missing JSON field \"channels\" in ChannelListResponse")
	}
	if _, ok := decoded["total"]; !ok {
		t.Error("missing JSON field \"total\" in ChannelListResponse")
	}
}
