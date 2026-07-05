package config

import (
	"os"
	"path/filepath"
	"testing"
)

func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}
	return path
}

const testConfigYAML = `
server:
  port: 9090
  host: "127.0.0.1"
database:
  sqlite:
    path: "/tmp/test.db"
auth:
  jwt_secret: "test-secret-which-must-be-at-least-32-chars"
  token_expiry: "12h"
heartbeat:
  default_interval: 60
  timeout: 10
  retention_days: 14
prometheus:
  enabled: true
  metrics_path: "/metrics"
dashboard:
  data_source_type: "prometheus"
  prometheus_url: "http://localhost:9090"
storage:
  upload_path: "/tmp/uploads"
  max_file_size: 52428800
`

func TestLoadFromYAML(t *testing.T) {
	path := createTempConfig(t, testConfigYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify Server
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %s, want 127.0.0.1", cfg.Server.Host)
	}

	// Verify Database
	if cfg.Database.SQLite.Path != "/tmp/test.db" {
		t.Errorf("Database.SQLite.Path = %s, want /tmp/test.db", cfg.Database.SQLite.Path)
	}

	// Verify Auth
	if cfg.Auth.JWTSecret != "test-secret-which-must-be-at-least-32-chars" {
		t.Errorf("Auth.JWTSecret = %s, want test-secret-which-must-be-at-least-32-chars", cfg.Auth.JWTSecret)
	}
	// Verify Heartbeat
	if cfg.Heartbeat.DefaultInterval != 60 {
		t.Errorf("Heartbeat.DefaultInterval = %d, want 60", cfg.Heartbeat.DefaultInterval)
	}
	if cfg.Heartbeat.RetentionDays != 14 {
		t.Errorf("Heartbeat.RetentionDays = %d, want 14", cfg.Heartbeat.RetentionDays)
	}

	// Verify Prometheus
	if !cfg.Prometheus.Enabled {
		t.Error("Prometheus.Enabled = false, want true")
	}

	// Verify Dashboard
	if cfg.Dashboard.DataSourceType != "prometheus" {
		t.Errorf("Dashboard.DataSourceType = %s, want prometheus", cfg.Dashboard.DataSourceType)
	}

	// Verify Storage
	if cfg.Storage.UploadPath != "/tmp/uploads" {
		t.Errorf("Storage.UploadPath = %s, want /tmp/uploads", cfg.Storage.UploadPath)
	}
	if cfg.Storage.MaxFileSize != 52428800 {
		t.Errorf("Storage.MaxFileSize = %d, want 52428800", cfg.Storage.MaxFileSize)
	}
}



func TestValidationValidSQLite(t *testing.T) {
	cfg := &Config{
		Auth: AuthConfig{
			JWTSecret: "a-32-char-secret-for-testing-purposes",
		},
	}

	if err := Validate(cfg); err != nil {
		t.Errorf("Validate failed: %v", err)
	}
}

